// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/state"
	"github.com/google/syzkaller/prog"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	nextFileNum := len(GetAllFiles(fuzzer.progsDir)) + 1
	env, err := ipc.GetSimpleEnv(fuzzer.config, pid, nextFileNum)
	if err != nil {
		return nil, err
	}
	env.ProgsRoot = fuzzer.progsDir
	env.PayloadsRoot = fuzzer.payloadDir
	env.SigCovStateRoot = fuzzer.sigcovstateDir
	print("boardserver: ", fuzzer.boardServer, "\n")
	env.Conn, err = net.Dial("tcp", fuzzer.boardServer)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

/* not used */
func WriteStringToFile(filename string, data string) {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("open file failed", err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	write.WriteString(data)
	write.Flush()
}

func (proc *Proc) loop() {

	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}

	for i := 0; ; i++ {
		if proc.fuzzer.stateFlag == "3" || proc.fuzzer.stateFlag == "4" { /* 3: syzkaller + minimizenoarg + schedule + state; 4: based on 3, dividestate*/
			
			if (i < 20) || (rand.Intn(i)%10 > 5) {
				item := proc.fuzzer.workQueue.dequeue()
				if item != nil {
					switch item := item.(type) {
					case *WorkTriage:
						proc.triageInputState(item) 
					case *WorkCandidate:
						proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
					case *WorkSmash: 
						log.Logf(0, "smash")
						proc.smashInput(item)
					default:
						log.Fatalf("unknown work type: %#v", item)
					}
					continue
				}
			} else {
				ct := proc.fuzzer.choiceTable
				fuzzerSnapshot := proc.fuzzer.snapshot()
				if len(fuzzerSnapshot.corpusStateHashes) == 0 || (rand.Intn(10)) < 2 { // 80% mutate and 20% generate
					p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
					log.Logf(0, "#%v: generated", proc.pid)
					proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
				} else {
					/* flag == 3 or 4: use mode 3 */
					tmp_corpus_item := fuzzerSnapshot.chooseProgramState(proc.rnd, 3)
					p := tmp_corpus_item.stateprog.Clone()
					p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
					log.Logf(0, "#%v: mutated", proc.pid)
					proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
				}
			}
		} else if proc.fuzzer.stateFlag == "5" { /* Syzkaller baseline + minimizenoarg + schedule + nosmash*/
			if (i < 20) || (rand.Intn(i)%10 > 5) {
				item := proc.fuzzer.workQueue.dequeue()
				if item != nil {
					switch item := item.(type) {
					case *WorkTriage:
						proc.triageInput(item)
					case *WorkCandidate:
						proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
					case *WorkSmash:
						proc.smashInput(item)
					default:
						log.Fatalf("unknown work type: %#v", item)
					}
					continue
				}
			} else {
				ct := proc.fuzzer.choiceTable
				fuzzerSnapshot := proc.fuzzer.snapshot()
				if len(fuzzerSnapshot.corpus) == 0 || (rand.Intn(10)) < 2 { // 80% mutate and 20% generate
					// Generate a new prog.
					p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
					log.Logf(0, "#%v: generated", proc.pid)
					proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
				} else {
					// Mutate an existing prog.
					p := fuzzerSnapshot.chooseProgram(proc.rnd, 1).Clone()
					p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
					log.Logf(0, "#%v: mutated", proc.pid)
					proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
				}
			}
		} else if proc.fuzzer.stateFlag == "6" || proc.fuzzer.stateFlag == "2" { /* 6: FState, no distillation , 2: State, no distillation*/
			item := proc.fuzzer.workQueue.dequeue()
			if item != nil {
				switch item := item.(type) {
				case *WorkTriage:
					proc.triageInputState(item) 
				case *WorkCandidate:
					proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				case *WorkSmash:
					log.Logf(0, "smash")
					proc.smashInput(item)
				default:
					log.Fatalf("unknown work type: %#v", item)
				}
				continue
			}
			ct := proc.fuzzer.choiceTable
			fuzzerSnapshot := proc.fuzzer.snapshot()
			if len(fuzzerSnapshot.corpusStateHashes) == 0 || (rand.Intn(10)) < 2 { // 80% mutate and 20% generate
				p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(0, "#%v: generated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			} else {
				/* flag == 3 or 4: use mode 3 */
				tmp_corpus_item := fuzzerSnapshot.chooseProgramState(proc.rnd, 3)
				p := tmp_corpus_item.stateprog.Clone()
				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: mutated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			}
		} else if proc.fuzzer.stateFlag == "7" { /* based on mode 6 sometime signal guided, sometime state guided*/
			item := proc.fuzzer.workQueue.dequeue()
			if item != nil {
				switch item := item.(type) {
				case *WorkTriage:
					proc.triageInputState(item)
				case *WorkCandidate:
					proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				case *WorkSmash: /* prog + interesting call location */
					log.Logf(0, "smash")
					proc.smashInput(item)
				default:
					log.Fatalf("unknown work type: %#v", item)
				}
				continue
			}
			ct := proc.fuzzer.choiceTable
			fuzzerSnapshot := proc.fuzzer.snapshot()
			if len(fuzzerSnapshot.corpusStateHashes) == 0 || (rand.Intn(10)) < 2 { // 80% mutate and 20% generate
				// Generate a new prog.
				p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(0, "#%v: generated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			} else {
				/* flag == 3 or 4: use mode 3 */
				var p *prog.Prog
				if rand.Intn(10) < 6 {
					tmp_corpus_item := fuzzerSnapshot.chooseProgramState(proc.rnd, 3)
					p = tmp_corpus_item.stateprog.Clone()
				} else {
					p = fuzzerSnapshot.chooseProgram(proc.rnd, 1).Clone()
				}

				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: mutated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			}
		} else if proc.fuzzer.stateFlag == "8" { /* baseline + no distillation, no state + smash */
			item := proc.fuzzer.workQueue.dequeue()
			if item != nil {
				switch item := item.(type) {
				case *WorkTriage:
					proc.triageInput(item)
				case *WorkCandidate:
					proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				case *WorkSmash:
					proc.smashInput(item)
				default:
					log.Fatalf("unknown work type: %#v", item)
				}
				continue
			}

			ct := proc.fuzzer.choiceTable
			fuzzerSnapshot := proc.fuzzer.snapshot()
			if len(fuzzerSnapshot.corpus) == 0 || (rand.Intn(10)) < 2 { // 80% mutate and 20% generate
				p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(0, "#%v: generated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			} else {
				// Mutate an existing prog.
				p := fuzzerSnapshot.chooseProgram(proc.rnd, 1).Clone()
				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: mutated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			}
		} else if proc.fuzzer.stateFlag == "9" { /* baseline + no distillation, no state + nosmash*/
			item := proc.fuzzer.workQueue.dequeue()
			if item != nil {
				switch item := item.(type) {
				case *WorkTriage:
					proc.triageInput(item)
				case *WorkCandidate:
					proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				case *WorkSmash:
					proc.smashInput(item)
				default:
					log.Fatalf("unknown work type: %#v", item)
				}
				continue
			}

			ct := proc.fuzzer.choiceTable
			fuzzerSnapshot := proc.fuzzer.snapshot()
			if len(fuzzerSnapshot.corpus) == 0 || (rand.Intn(10)) < 2 { // 80% mutate and 20% generate
				// Generate a new prog.
				p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(0, "#%v: generated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			} else {
				// Mutate an existing prog.
				p := fuzzerSnapshot.chooseProgram(proc.rnd, 1).Clone()
				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: mutated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			}
		} else if proc.fuzzer.stateFlag == "10" { /* new state caculate algorithm */
			item := proc.fuzzer.workQueue.dequeue()
			if item != nil {
				switch item := item.(type) {
				case *WorkTriage:
					proc.triageInputState(item)
				case *WorkCandidate:
					proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				case *WorkSmash: /* prog + interesting call location */
					log.Logf(0, "smash")
					proc.smashInput(item)
				default:
					log.Fatalf("unknown work type: %#v", item)
				}
				continue
			}
			ct := proc.fuzzer.choiceTable
			fuzzerSnapshot := proc.fuzzer.snapshot()
			if len(fuzzerSnapshot.corpus) == 0 || (rand.Intn(10)) < 2 { // 80% mutate and 20% generate
				p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(0, "#%v: generated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			} else {
				/* flag == 3 or 4 or 6 or 2: use mode 3, choose state, then choose seed; flag == 10, mode 4 choose seed based on prio + hittimes*/
				p := fuzzerSnapshot.chooseProgram(proc.rnd, 4)
				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: mutated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			}
		} else { //syzkaller baseline  1
			item := proc.fuzzer.workQueue.dequeue()
			if item != nil {
				switch item := item.(type) {
				case *WorkTriage:
					proc.triageInput(item)
				case *WorkCandidate:
					proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				case *WorkSmash:
					proc.smashInput(item)
				default:
					log.Fatalf("unknown work type: %#v", item)
				}
				continue
			}

			ct := proc.fuzzer.choiceTable
			fuzzerSnapshot := proc.fuzzer.snapshot()
			if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
				// Generate a new prog.
				p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
				log.Logf(0, "#%v: generated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			} else {
				// Mutate an existing prog.
				p := fuzzerSnapshot.chooseProgram(proc.rnd, 1).Clone()
				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "#%v: mutated", proc.pid)
				proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			}
		}
	}
}

func (proc *Proc) triageInputState(item *WorkTriage) {
	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	inputState := state.FromRawState(item.info.State) /* may be new state, or new sig but old state */
	var inputStateMap state.MapStateSlice
	if proc.fuzzer.stateFlag == "3" || proc.fuzzer.stateFlag == "2" {
		inputStateMap = state.ConstructMapStateSlice(inputState)
	} else if proc.fuzzer.stateFlag == "4" || proc.fuzzer.stateFlag == "6" || proc.fuzzer.stateFlag == "10" || proc.fuzzer.stateFlag == "7" {
		inputStateMap = state.ConstructMapDivideStateSlice(inputState, proc.fuzzer.handleDivision)
	}
	_ = proc.fuzzer.corpusStateDiff(inputStateMap)
	var statevariables hash.StateValues
	if proc.fuzzer.stateFlag == "4" || proc.fuzzer.stateFlag == "6" || proc.fuzzer.stateFlag == "10" || proc.fuzzer.stateFlag == "7" {
		statevariables = state.CalculateDivideStateVariables(item.info.State[1], item.info.State[2], proc.fuzzer.handleDivision)
	} else {
		statevariables = state.CalculateStateVariables(item.info.State[1], item.info.State[2])
	}
	_, ok := proc.fuzzer.corpusStateHashes[statevariables]
	if newSignal.Empty() && ok {
		return
	}
	thisCover := item.info.Cover
	var inputCover cover.Cover
	inputCover.Merge(thisCover)
	callName := ".extra"
	_ = "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		_ = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	const (
		//signalRuns       = 1
		minimizeAttempts = 1
	)
	fmt.Printf("mode state: %b", StatTriage)
	if proc.fuzzer.stateFlag != "6" && proc.fuzzer.stateFlag != "2" && proc.fuzzer.stateFlag != "10" && proc.fuzzer.stateFlag != "7" {
		if item.flags&ProgMinimized == 0 {
			item.p, item.call = prog.MinimizeNoArg(item.p, item.call, false,
				func(p1 *prog.Prog, call1 int) bool {
					for i := 0; i < minimizeAttempts; i++ {
						info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
						if !reexecutionSuccess(info, &item.info, call1) {
							// The call was not executed or failed.
							continue
						}
						thisSignal, _ := getSignalAndCover(p1, info, call1)
						thisStateValues := getState(p1, info, call1)
						/* check if current syscall's state value changes */
						var thisStateHash hash.StateValues
						var inputStateHash hash.StateValues
						if proc.fuzzer.stateFlag == "3" {
							thisStateHash = state.CalculateStateVariables(thisStateValues[1], thisStateValues[2])
							inputStateHash = state.CalculateStateVariables(inputState[1], inputState[2])
						} else if proc.fuzzer.stateFlag == "4" {
							thisStateHash = state.CalculateDivideStateVariables(thisStateValues[1], thisStateValues[2], proc.fuzzer.handleDivision)
							inputStateHash = state.CalculateDivideStateVariables(inputState[1], inputState[2], proc.fuzzer.handleDivision)
						}
						if newSignal.Intersection(thisSignal).Len() == newSignal.Len() && thisStateHash == inputStateHash {
							return true
						}
					}
					return false
				})
		}
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	if proc.fuzzer.stateFlag == "10" {
		proc.fuzzer.addInputToCorpusState(item.p, inputSignal, sig, statevariables, item.call)
	} else {
		proc.fuzzer.addInputToStateCorpus(item.p, inputSignal, sig, statevariables, item.call)
		proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)
	}

	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})
}


func (proc *Proc) triageInput(item *WorkTriage) {
	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)

	notexecuted := 0
	if proc.fuzzer.stateFlag == "1" { /* triage syzkaller baseline */
		for i := 0; i < signalRuns; i++ {
			info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
			if !reexecutionSuccess(info, &item.info, item.call) {
				// The call was not executed or failed.
				notexecuted++
				if notexecuted > signalRuns/2+1 {
					return // if happens too often, give up
				}
				continue
			}
			thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
			newSignal = newSignal.Intersection(thisSignal)
			// Without !minimized check manager starts losing some considerable amount
			// of coverage after each restart. Mechanics of this are not completely clear.
			if newSignal.Empty() && item.flags&ProgMinimized == 0 {
				return
			}
			inputCover.Merge(thisCover)
		}
	} else {
		fmt.Printf("mode %v triage: %b", proc.fuzzer.stateFlag, StatTriage)
	}
	if proc.fuzzer.stateFlag == "8" || proc.fuzzer.stateFlag == "9" { /* no minimize */

	} else {
		if item.flags&ProgMinimized == 0 {
			if proc.fuzzer.stateFlag == "5" || proc.fuzzer.stateFlag == "7" {
				const (
					minimizeattemptsNew = 1
				)
				item.p, item.call = prog.MinimizeNoArg(item.p, item.call, false,
					func(p1 *prog.Prog, call1 int) bool {
						for i := 0; i < minimizeattemptsNew; i++ {
							info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
							if !reexecutionSuccess(info, &item.info, call1) {
								// The call was not executed or failed.
								continue
							}
							thisSignal, _ := getSignalAndCover(p1, info, call1)
							if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
								return true
							}
						}
						return false
					})
				log.Logf(0, "end minimize function")
			} else {
				item.p, item.call = prog.Minimize(item.p, item.call, false,
					func(p1 *prog.Prog, call1 int) bool {
						for i := 0; i < minimizeAttempts; i++ {
							info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
							if !reexecutionSuccess(info, &item.info, call1) {
								// The call was not executed or failed.
								continue
							}
							thisSignal, _ := getSignalAndCover(p1, info, call1)
							if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
								return true
							}
						}
						return false
					})
			}

		}
	}
	data := item.p.Serialize()
	sig := hash.Hash(data)

	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)
	if proc.fuzzer.stateFlag != "5" && proc.fuzzer.stateFlag != "7" && proc.fuzzer.stateFlag != "9" {
		if item.flags&ProgSmashed == 0 {
			proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
		}
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func getState(p *prog.Prog, info *ipc.ProgInfo, call int) state.State {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return state.FromRawState(inf.State)
}


func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func Union(a, b []int) []int {
	m := make(map[int]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; !ok {
			a = append(a, item)
		}
	}
	return a
}


func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}

	calls, extra := proc.fuzzer.checkNewSignal(p, info) 
	if proc.fuzzer.stateFlag == "3" || proc.fuzzer.stateFlag == "2" {
		newStateCalls := proc.fuzzer.checkNewState(p, info, "3") 
		calls = Union(newStateCalls, calls)
	}
	if proc.fuzzer.stateFlag == "4" || proc.fuzzer.stateFlag == "6" || proc.fuzzer.stateFlag == "10" || proc.fuzzer.stateFlag == "7" {
		newStateCalls := proc.fuzzer.checkNewState(p, info, "4")
		calls = Union(calls, newStateCalls)
	}

	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	info.Signal = append([]uint32{}, info.Signal...)
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {

	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	proc.fuzzer.checkDisabledCalls(p)

	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)
	_, sigFileName, covFileName, stateFileName, payload := proc.logProgram(opts, p)
	// Ignore payloads larger than 0x4000 bytes.
	if len(payload) > 0x4000 {
		return nil
	}

	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		goIndex := make([]byte, 4)
		binary.LittleEndian.PutUint32(goIndex, uint32(proc.env.NextFileNum-1))
		newPayload := append(goIndex, payload...)
		output, info, hanged, err := proc.env.ExecPayload(newPayload, p)
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil
			}
			if try > 0 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			continue
		}
		if (info != nil) && (len(p.Calls) > 0) {
			proc.logSig(info, sigFileName)
			log.Logf(2, "sig logged")
			proc.logCov(info, covFileName)
			log.Logf(2, "cov logged")
			proc.logState(info, p, stateFileName)
		}

		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}


func GetAllFiles(dirname string) (res []string) {
	rd, err := ioutil.ReadDir(dirname)
	if err != nil {
		return
	}
	for _, item := range rd {
		if item.IsDir() {
			tmp := GetAllFiles(dirname + "/" + item.Name())
			res = append(res, tmp...)
		} else {
			res = append(res, dirname+"/"+item.Name())
		}
	}
	return
}

func (proc *Proc) getNewFileNames() (progName, payloadName, sigName, covName, stateName string) {

	currentFileNumStr := strconv.Itoa(proc.env.NextFileNum)
	proc.env.NextFileNum += 1
	progName = path.Join(proc.env.ProgsRoot, "prog-"+currentFileNumStr+".txt")
	payloadName = path.Join(proc.env.PayloadsRoot, "payload-"+currentFileNumStr)
	sigName = path.Join(proc.env.SigCovStateRoot, "sig-"+currentFileNumStr+".txt")
	covName = path.Join(proc.env.SigCovStateRoot, "cov-"+currentFileNumStr+".txt")
	stateName = path.Join(proc.env.SigCovStateRoot, "state-"+currentFileNumStr+".txt")

	return
}


func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) (payloadFileName, sigFileName, covFileName, stateFileName string, payload []byte) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	syscalls, payload := p.GeneratePayload()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		var progFileName string
		progFileName, payloadFileName, sigFileName, covFileName, stateFileName = proc.getNewFileNames()
		err := osutil.WriteFile(progFileName, syscalls)
		if err != nil {
			fmt.Printf("%v", err)
			return
		}
		err = osutil.WriteFile(payloadFileName, payload)
		if err != nil {
			fmt.Printf("%v", err)
			return
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
	return
}

func (proc *Proc) logState(info *ipc.ProgInfo, p *prog.Prog, stateFileName string) {
	file, err := os.OpenFile(stateFileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("open file failed", err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	prog_index := 0
	for i := 0; i < len(info.States); i++ {
		if len(p.Calls[i].Meta.CallName) > 0 {
			if find := strings.Contains(p.Calls[i].Meta.CallName, "TA_"); find {
				continue
			} else {
				write.WriteString("[Syscall " + strconv.Itoa(prog_index) + "]:")
				write.WriteString("[OperationHandle Start]:" + strconv.Itoa(len(info.States[i][1])))
				for j := 0; j < len(info.States[i][1]); j++ {
					write.Write(info.States[i][1][j])
					write.WriteString("[syztrust]")
				}
				write.WriteString("[ObjectHandle Start]:" + strconv.Itoa(len(info.States[i][2])))
				for k := 0; k < len(info.States[i][2]); k++ {
					write.Write(info.States[i][2][k])
					write.WriteString("[syztrust]")
				}
				write.WriteString("[end]\n")
				write.Flush()
				prog_index = prog_index + 1
			}
		}
	}

}

func (proc *Proc) logSig(info *ipc.ProgInfo, sigFileName string) {
	file, err := os.OpenFile(sigFileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("open file failed", err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	for i := 0; i < len(info.Calls); i++ {
		write.WriteString("Syscall " + strconv.Itoa(i) + ": \n")
		for j := 0; j < len(info.Calls[i].Signal); j++ {
			write.WriteString(strconv.FormatUint(uint64(info.Calls[i].Signal[j]), 10))
			write.WriteString("\n")
		}
	}
	write.Flush()

}

func (proc *Proc) logCov(info *ipc.ProgInfo, covFileName string) {
	file, err := os.OpenFile(covFileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("open file failed", err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	for i := 0; i < len(info.Calls); i++ {
		write.WriteString("Syscall " + strconv.Itoa(i) + ": \n")
		for j := 0; j < len(info.Calls[i].Cover); j++ {
			write.WriteString(strconv.FormatUint(uint64(info.Calls[i].Cover[j]), 10))
			write.WriteString("\n")
		}
	}
	write.Flush()

}