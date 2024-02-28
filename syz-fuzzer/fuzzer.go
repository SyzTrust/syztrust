// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/state"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type corpus_item struct {
	call      int
	stateprog *prog.Prog
}
type StateCorpus struct {
	corpusMu     sync.RWMutex
	corpus       []corpus_item
	corpusHashes map[hash.Sig]struct{}
	corpusPrios  []int64
	sumPrios     int64
}

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	stats             [StatCount]uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}
	corpusPrios  []int64
	sumPrios     int64

	signalMu     sync.RWMutex
	corpusSignal signal.Signal 
	maxSignal    signal.Signal
	newSignal    signal.Signal

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex

	corpusHitState [][]hash.StateValues
	maxStates      state.MapStateSlice
	newStates      state.MapStateSlice
	corpusStates   state.MapStateSlice
	stateW         state.StateWeights
	sumW           float32
	statesMu       sync.RWMutex

	progsDir       string
	payloadDir     string
	sigcovstateDir string
	boardServer    string
	commandPython  string
	stateRefine    string
	corpusFile     string
	traceID        string
	handleDivision string
	stateMu           sync.RWMutex 
	stateCorpusMu     sync.RWMutex
	corpusStateHashes map[hash.StateValues]*StateCorpus

	chosedSeed     []*prog.Prog
	seedPrios      []int64
	seedsumPrios   int64
	seedIdinCorpus []int64
	stateFlag      string

}

type FuzzerSnapshot struct {
	corpus      []*prog.Prog
	corpusPrios []int64
	sumPrios    int64
	corpusHitState    [][]hash.StateValues
	maxStates         state.MapStateSlice
	stateW            state.StateWeights
	sumW              float32
	commandPython     string
	stateRefine       string
	traceID           string
	chosedSeed        []*prog.Prog
	seedPrios         []int64
	seedsumPrios      int64
	seedIdinCorpus    []int64
	corpusStateHashes map[hash.StateValues]*StateCorpus
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
}

// nolint: funlen
func main() {
	main0()
	debug.SetGCPercent(50)
	var (
		flagName    = flag.String("name", "test", "unique name for manager")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest    = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}

	log.Logf(0, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.Fatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}
	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		timeouts:                 timeouts,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		checkResult:              r.CheckResult,
		corpusStateHashes: make(map[hash.StateValues]*StateCorpus),
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	// gate limits concurrency level and window to the given value.
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)

	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzer.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			len(fuzzer.corpus), len(fuzzer.corpusSignal), len(fuzzer.maxSignal))
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}

	// Make directories for progs and payloads
	if !osutil.IsExist(r.ProgsDir) {
		err = os.Mkdir(r.ProgsDir, os.ModePerm)
	}
	if !osutil.IsExist(r.PayloadDir) {
		err = os.Mkdir(r.PayloadDir, os.ModePerm)
	}
	if !osutil.IsExist(r.SigCovStateDir) {
		err = os.Mkdir(r.SigCovStateDir, os.ModePerm)
	}
	fuzzer.progsDir = r.ProgsDir
	fuzzer.payloadDir = r.PayloadDir
	fuzzer.sigcovstateDir = r.SigCovStateDir
	fuzzer.boardServer = r.BoardServer
	fuzzer.commandPython = r.CommandPython
	fuzzer.stateRefine = r.StateRefine
	fuzzer.corpusFile = r.CorpusFile
	fuzzer.traceID = r.TraceID
	fuzzer.stateFlag = r.StateFlag
	fuzzer.handleDivision = r.HandleDivision
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)

	if r.CoverFilterBitmap != nil {
		fuzzer.execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}
	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("fuzzer.go: failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.Fatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.Fatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := fuzzer.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * fuzzer.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * fuzzer.timeouts.Scale).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*fuzzer.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second*fuzzer.timeouts.Scale {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		MaxStates:      fuzzer.grabNewStates().Serialize(),
		Stats:          stats,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	maxStates := r.MaxStates.Deserialize()
	fuzzer.addMaxStates(maxStates)
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v state=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len(), len(maxStates))
	fuzzer.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.RPCInput) {
	a := &rpctype.NewInputArgs{
		Name:     fuzzer.name,
		RPCInput: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.RPCInput) { 
	p := fuzzer.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.RPCCandidate) {
	p := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) *prog.Prog {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	// We build choice table only after we received the initial corpus,
	// so we don't check the initial corpus here, we check it later in BuildChoiceTable.
	if fuzzer.choiceTable != nil {
		fuzzer.checkDisabledCalls(p)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (fuzzer *Fuzzer) checkDisabledCalls(p *prog.Prog) {
	for _, call := range p.Calls {
		if !fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(fuzzer.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range fuzzer.checkResult.EnabledCalls[sandbox] {
				meta := fuzzer.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range fuzzer.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, fuzzer.choiceTable.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

func (fuzzer *FuzzerSnapshot) addSeedtoChosedSeed(seed_calls []string) {
	for i := 0; i < len(fuzzer.corpus); i++ {
		if fuzzer.testSeedEq(seed_calls, fuzzer.corpus[i]) {
			fuzzer.chosedSeed = append(fuzzer.chosedSeed, fuzzer.corpus[i])
			if i > 0 {
				fuzzer.seedsumPrios += fuzzer.corpusPrios[i] - fuzzer.corpusPrios[i-1]
			} else {
				fuzzer.seedsumPrios += fuzzer.corpusPrios[0]
			}
			fuzzer.seedPrios = append(fuzzer.seedPrios, fuzzer.seedsumPrios)
			fuzzer.seedIdinCorpus = append(fuzzer.seedIdinCorpus, int64(i))
		}
	}
}

//check if seeds equals a prog.calls by callname
func (fuzzer *FuzzerSnapshot) testSeedEq(seed_calls []string, prog *prog.Prog) bool {
	var corpus_sysycalls []string
	for j := range prog.Calls {
		if strings.HasPrefix(prog.Calls[j].Meta.CallName, "TA_") {

		} else {
			corpus_sysycalls = append(corpus_sysycalls, prog.Calls[j].Meta.CallName)
		}
	}
	if (seed_calls == nil) != (corpus_sysycalls == nil) {
		return false
	}

	if len(seed_calls) != len(corpus_sysycalls) {
		return false
	}

	for i := range seed_calls {
		if seed_calls[i] != corpus_sysycalls[i] {
			return false
		}
	}
	log.Logf(0, "Matched!")
	return true

}

func WeightedRandomIndex(stateW state.StateWeights, sum float32) hash.StateValues {
	r := rand.Float32() * sum
	var finalkey hash.StateValues
	var t float32 = 0.0
	for key := range stateW {
		t += stateW[key]
		if t > r {
			return key
		}
		finalkey = key
	}
	return finalkey
}

func (fuzzer *FuzzerSnapshot) chooseProgramState(r *rand.Rand, mode uint32) corpus_item {
	var statevariables hash.StateValues

	if mode == 2 { /* mode random choose*/
		i := r.Intn(len(fuzzer.maxStates))
		statevariables = fuzzer.maxStates.GetKeys()[i]
	} else if mode == 3 { /* mode 3 based on the hitnums */
		statevariables = WeightedRandomIndex(fuzzer.stateW, fuzzer.sumW)
	}
	selected_state := statevariables
	if _, ok := fuzzer.corpusStateHashes[statevariables]; !ok {

		states_len := len(fuzzer.corpusStateHashes)
		mapKeys := make([]hash.StateValues, 0, states_len)
		for key := range fuzzer.corpusStateHashes {
			mapKeys = append(mapKeys, key)
		}
		selected_state = mapKeys[rand.Intn(len(mapKeys))]
	}
	randVal := r.Int63n(fuzzer.corpusStateHashes[selected_state].sumPrios + 1)

	idx := sort.Search(len(fuzzer.corpusStateHashes[selected_state].corpusPrios), func(i int) bool {
		return fuzzer.corpusStateHashes[selected_state].corpusPrios[i] >= randVal
	})
	return fuzzer.corpusStateHashes[selected_state].corpus[idx]

}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand, mode uint32) *prog.Prog {
	if mode == 4 {
		/* define the threshold of rarely visited states */
		states_sum := len(fuzzer.maxStates)
		var hit_sum int
		for state := range fuzzer.maxStates {
			hit_sum = hit_sum + fuzzer.maxStates[state]
		}
		threshold := hit_sum / states_sum
		var rarestate_sum int
		for state := range fuzzer.maxStates {
			if fuzzer.maxStates[state] < threshold {
				rarestate_sum += 1
			}
		}
		len_seeds := len(fuzzer.corpus)
		newCorpusPrio := make([]float32, len_seeds)
		var newsumPrio float32 = 0.0
		var p_rarestate int
		for i := 0; i < len_seeds; i++ {
			rarestates := make(map[hash.StateValues]int)
			for _, state := range fuzzer.corpusHitState[i] {
				if fuzzer.maxStates[state] < threshold {
					if _, ok := rarestates[state]; !ok {
						rarestates[state] = 1
						p_rarestate += 1
					}
				}
			}
			tmp := float32(fuzzer.corpusPrios[i]) * float32(p_rarestate) / float32(rarestate_sum)
			new_Prio_tmp := float32(fuzzer.corpusPrios[i]) + tmp
			newCorpusPrio[i] = newsumPrio + new_Prio_tmp
			newsumPrio = newsumPrio + new_Prio_tmp
		}
		randVal := rand.Float32() * newsumPrio
		idx := sort.Search(len(newCorpusPrio), func(i int) bool {
			return newCorpusPrio[i] >= randVal
		})
		return fuzzer.corpus[idx]
	} else {
		randVal := r.Int63n(fuzzer.sumPrios + 1)
		idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
			return fuzzer.corpusPrios[i] >= randVal
		})
		return fuzzer.corpus[idx]
	}
}

func (fuzzer *Fuzzer) loadSeedIntoCorpusFile(CorpusFile string, p *prog.Prog) {

	file, err := os.OpenFile(CorpusFile, os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("open file failed, error: %v\n", err)
		return
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for j := 0; j < len(p.Calls); j++ {
		tmpCallName := p.Calls[j].Meta.Name
		if j != 0 {
			writer.WriteString(" ")
		}
		writer.WriteString(tmpCallName)
	}
	writer.WriteString("\n")
	writer.Flush()

}

func (fuzzer *Fuzzer) addInputToStateCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig, statevalues hash.StateValues, call int) {
	fuzzer.stateCorpusMu.Lock()
	if _, ok := fuzzer.corpusStateHashes[statevalues]; !ok {
		fuzzer.corpusStateHashes[statevalues] = &StateCorpus{
			corpusHashes: make(map[hash.Sig]struct{}),
		}
		stateCorpus := fuzzer.corpusStateHashes[statevalues]
		stateCorpus.corpusMu.Lock()
		prog_item := corpus_item{}
		prog_item.call = call
		prog_item.stateprog = p
		stateCorpus.corpus = append(stateCorpus.corpus, prog_item)
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		stateCorpus.sumPrios += prio
		stateCorpus.corpusPrios = append(stateCorpus.corpusPrios, stateCorpus.sumPrios)
		stateCorpus.corpusMu.Unlock()

		if !sign.Empty() {
			fuzzer.signalMu.Lock()
			fuzzer.corpusSignal.Merge(sign)
			fuzzer.maxSignal.Merge(sign)
			fuzzer.signalMu.Unlock()
		}
		if len(statevalues) != 0 {
			fuzzer.statesMu.Lock()
			tmp_map := make(map[hash.StateValues]int)
			tmp_map[statevalues] = 1
			fuzzer.corpusStates.Merge(tmp_map)
			fuzzer.statesMu.Unlock()
		}
	} else { /* no new state but new sig, use existed state */
		stateCorpus := fuzzer.corpusStateHashes[statevalues]
		stateCorpus.corpusMu.Lock()
		prog_item := corpus_item{}
		prog_item.call = call
		prog_item.stateprog = p
		stateCorpus.corpus = append(stateCorpus.corpus, prog_item)
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		stateCorpus.sumPrios += prio
		stateCorpus.corpusPrios = append(stateCorpus.corpusPrios, stateCorpus.sumPrios)
		stateCorpus.corpusMu.Unlock()
		if !sign.Empty() {
			fuzzer.signalMu.Lock()
			fuzzer.corpusSignal.Merge(sign)
			fuzzer.maxSignal.Merge(sign)
			fuzzer.signalMu.Unlock()
		}
	}
	fuzzer.stateCorpusMu.Unlock()
}

func (fuzzer *Fuzzer) addInputToCorpusState(p *prog.Prog, sign signal.Signal, sig hash.Sig, statevalues hash.StateValues, call int) {
	fuzzer.stateCorpusMu.Lock()
	fuzzer.corpusMu.Lock()

	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		index := fuzzer.Index(p, fuzzer.corpus)
		if index == -1 {
			fuzzer.corpus = append(fuzzer.corpus, p)
			fuzzer.corpusHashes[sig] = struct{}{}
			prio := int64(len(sign))
			if sign.Empty() {
				prio = 1
			}
			fuzzer.sumPrios += prio
			fuzzer.corpusPrios = append(fuzzer.corpusPrios, prio)
			tmpHitStates := make([]hash.StateValues, 20)
			tmpHitStates = append(tmpHitStates, statevalues)
			fuzzer.corpusHitState = append(fuzzer.corpusHitState, tmpHitStates)
			fuzzer.corpusPrios = append(fuzzer.corpusPrios, prio)
		}
	} else {
		index := fuzzer.Index(p, fuzzer.corpus)
		if index == -1 {
			fuzzer.corpus = append(fuzzer.corpus, p)
			fuzzer.corpusHashes[sig] = struct{}{}
			prio := int64(len(sign))
			if sign.Empty() {
				prio = 1
			}
			fuzzer.sumPrios += prio
			fuzzer.corpusPrios = append(fuzzer.corpusPrios, prio)
			tmpHitStates := make([]hash.StateValues, 20)
			tmpHitStates = append(tmpHitStates, statevalues)
			fuzzer.corpusHitState = append(fuzzer.corpusHitState, tmpHitStates)
		} else {
			tmpHitStates := fuzzer.corpusHitState[index]
			tmpHitStates = append(tmpHitStates, statevalues)
			fuzzer.corpusHitState[index] = tmpHitStates
		}
	}
	fuzzer.loadSeedIntoCorpusFile(fuzzer.corpusFile, p)
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
	fuzzer.stateCorpusMu.Unlock()
}


func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		fuzzer.sumPrios += prio
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)
	}
	fuzzer.loadSeedIntoCorpusFile(fuzzer.corpusFile, p) // load seeds to CorpusFile
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) Index(p *prog.Prog, corpus []*prog.Prog) int {
	if n := len(corpus); corpus != nil && n != 0 {
		i := 0
		for !reflect.DeepEqual(p, corpus[i]) {
			i++
			if i >= n {
				break
			}
		}

		if i != n {
			return i
		}
	}
	return -1
}


func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{fuzzer.corpus, fuzzer.corpusPrios, fuzzer.sumPrios, fuzzer.corpusHitState, fuzzer.maxStates, fuzzer.stateW, fuzzer.sumW, fuzzer.commandPython, fuzzer.stateRefine, fuzzer.traceID, fuzzer.chosedSeed, fuzzer.seedPrios, fuzzer.seedsumPrios, fuzzer.seedIdinCorpus, fuzzer.corpusStateHashes}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) addMaxStates(state state.MapStateSlice) {
	if len(state) == 0 {
		return
	}
	fuzzer.statesMu.Lock()
	defer fuzzer.statesMu.Unlock()
	fuzzer.maxStates.MergeMaxState(state)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) grabNewStates() state.MapStateSlice {
	fuzzer.statesMu.Lock()
	defer fuzzer.statesMu.Unlock()
	states := fuzzer.newStates
	if states.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return states
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) corpusStateDiff(state state.MapStateSlice) state.MapStateSlice {
	fuzzer.statesMu.RLock()
	defer fuzzer.statesMu.RUnlock()
	return fuzzer.corpusStates.Diff(state)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if fuzzer.stateFlag == "1" {
			if strings.HasPrefix(p.Calls[i].Meta.CallName, "TA_") {
				continue
			} else {
				fuzzer.checkNewCallSignal(p, &inf, i)
				{
					calls = append(calls, i)
				}
			}
		} else {
			if strings.HasPrefix(p.Calls[i].Meta.CallName, "TA_") {
				continue
			} else {
				if fuzzer.checkNewCallSignal(p, &inf, i) {
					calls = append(calls, i)
				}
			}
		}
	}
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) checkNewState(p *prog.Prog, info *ipc.ProgInfo, testflag string) (calls []int) {
	fuzzer.statesMu.RLock()
	defer fuzzer.statesMu.RUnlock()
	for i, call_state := range info.States {
		if strings.HasPrefix(p.Calls[i].Meta.CallName, "TA_") {
			continue
		}
		if len(call_state[1]) == 0 && (len(call_state[2]) == 0) {
			continue
		}
		if fuzzer.checkNewCallState(p, call_state, i, testflag) {
			calls = append(calls, i)
		}
	}
	return
}

func (fuzzer *Fuzzer) checkNewCallState(p *prog.Prog, call_state map[uint32][][]byte, call int, testflag string) bool {
	var diff state.MapStateSlice
	var call_statehash hash.StateValues
	if testflag == "3" {
		diff = fuzzer.maxStates.DiffHash(call_state)
		call_statehash = state.CalculateStateVariables(call_state[1], call_state[2])
	} else {
		diff = fuzzer.maxStates.DiffHashDivide(call_state, fuzzer.handleDivision)
		call_statehash = state.CalculateDivideStateVariables(call_state[1], call_state[2], fuzzer.handleDivision)
	}
	if diff.Empty() {
		var oldweight float32
		if _, ok := fuzzer.stateW[call_statehash]; !ok {
			oldweight = 0
		} else {
			oldweight = fuzzer.stateW[call_statehash]
		}
		if fuzzer.stateW == nil {
			fuzzer.sumW = 0
		}
		fuzzer.stateW.Merge(call_statehash, fuzzer.maxStates)
		fuzzer.sumW = fuzzer.sumW + fuzzer.stateW[call_statehash] - oldweight
		return false
	}
	fuzzer.statesMu.RUnlock()
	fuzzer.statesMu.Lock()
	fuzzer.maxStates.Merge(diff)
	/* update weights */
	var oldweight float32
	if _, ok := fuzzer.stateW[call_statehash]; !ok {
		oldweight = 0
	} else {
		oldweight = fuzzer.stateW[call_statehash]
	}
	if fuzzer.stateW == nil {
		fuzzer.sumW = 0
	}
	fuzzer.stateW.Merge(call_statehash, fuzzer.maxStates)
	fuzzer.sumW = fuzzer.sumW + fuzzer.stateW[call_statehash] - oldweight
	/* update weights */
	fuzzer.newStates.Merge(diff)
	for key := range diff {
		log.Logf(0, "merged new state: %x", key)
	}
	log.Logf(0, "new state len is %v, maxStates len is %v ", diff.Len(), fuzzer.maxSignal.Len())
	fuzzer.statesMu.Unlock()
	fuzzer.statesMu.RLock()
	return true

}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	log.Logf(0, "new signal len is %v, maxSignal len is %v ", diff.Len(), fuzzer.maxSignal.Len())
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}