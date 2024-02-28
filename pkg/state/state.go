package state

import (
	"bytes"
	"encoding/json"
	"github.com/google/syzkaller/pkg/hash"
	"sort"
)

type State map[uint32][][]byte

type StateSlice []State /* not used 20220811 */

type MapStateSlice map[hash.StateValues]int
type SerialHash []hash.StateValues

type StateSerial struct {
	Statevs  []hash.StateValues
	HitTimes []int
}

type StateWeights map[hash.StateValues]float32

func (s MapStateSlice) Len() int {
	return len(s)
}

func (s StateSlice) DiffRaw(s1 State) bool {
	for i := 0; i < len(s); i++ {
		if (testByteSEq(s1[1], s[i][1])) && (testByteSEq(s1[2], s[i][2])) {
			return false
		}
	}
	return true
}

func (s MapStateSlice) GetKeys() []hash.StateValues {
	j := 0
	keys := make([]hash.StateValues, len(s))
	for k := range s {
		keys[j] = k
		j++
	}
	return keys

}

func (s MapStateSlice) Empty() bool {
	return len(s) == 0
}

func (s MapStateSlice) Copy() MapStateSlice {
	c := make(map[hash.StateValues]int)
	for k := range s {
		c[k] = s[k]
	}
	return c
}

func (s MapStateSlice) Serialize() StateSerial {
	if s.Empty() {
		return StateSerial{}
	}
	res := StateSerial{
		Statevs:  make([]hash.StateValues, len(s)),
		HitTimes: make([]int, len(s)),
	}
	i := 0
	for k := range s {
		res.Statevs[i] = k
		res.HitTimes[i] = s[k]
		i++
	}
	return res
}

func (ser StateSerial) Deserialize() MapStateSlice {
	if len(ser.Statevs) != len(ser.HitTimes) {
		panic("corrupted StateSerial")
	}
	if len(ser.Statevs) == 0 {
		return nil
	}
	s := make(map[hash.StateValues]int)
	for i, v := range ser.Statevs {
		s[v] = ser.HitTimes[i]
	}
	return s
}

func (s MapStateSlice) DiffHash(s1 State) MapStateSlice {
	var res MapStateSlice
	s1Hash := CalculateStateVariables(s1[1], s1[2])
	if _, ok := s[s1Hash]; !ok {
		if res == nil {
			res = make(map[hash.StateValues]int)
		}
		res[s1Hash] = 1
	} else {
		s[s1Hash] = s[s1Hash] + 1 /* update state hit numbers */
	}
	return res
}
func (s MapStateSlice) DiffHashDivide(s1 State, handleDivision string) MapStateSlice {
	var res MapStateSlice

	s1Hash := CalculateDivideStateVariables(s1[1], s1[2], handleDivision)
	if _, ok := s[s1Hash]; !ok {
		if res == nil {
			res = make(map[hash.StateValues]int)
		}
		res[s1Hash] = 1
	} else {
		s[s1Hash] = s[s1Hash] + 1 /* update state hit numbers */
	}
	return res
}

func CalculateStateVariables(bl1 [][]byte, bl2 [][]byte) hash.StateValues {
	//bl1 := state_raw[1]
	//bl2 := state_raw[2]
	//log.Logf(0, "statevariables:  operationhandle len: %v, objecthandle len : %v", len(bl1), len(bl2))
	if len(bl1) > 0 {
		sort.Slice(bl1, func(i, j int) bool {
			flag := bytes.Compare(bl1[i], bl1[j])
			if flag < 0 {
				return true
			} else {
				return false
			}
		})
	}
	if len(bl2) > 0 {
		sort.Slice(bl2, func(i, j int) bool {
			flag := bytes.Compare(bl2[i], bl2[j])
			if flag < 0 {
				return true
			} else {
				return false
			}
		})
	}
	bl1_m := bytes.Join(bl1, []byte(""))
	bl2_m := bytes.Join(bl2, []byte(""))
	rawstate := append(bl1_m, bl2_m...)
	statevariables := hash.HashState(rawstate)
	return statevariables
}

func CalculateDivideStateVariables(bl1 [][]byte, bl2 [][]byte, handleDivision string) hash.StateValues {
	//bl1 := state_raw[1]
	//bl2 := state_raw[2]
	var division [][][]int
	_ = json.Unmarshal([]byte(handleDivision), &division)
	opdivide := division[0]
	objdivide := division[1]
	//opdivide := [][]int{{0, 31}, {40, 43}, {48, 51}, {52, 55}, {56, 59}, {60, 63}, {64, 67}}
	//objdivide := [][]int{{8, 35}, {36, 39}, {40, 43}, {48, 51}, {60, 63}}
	news11 := make([][]byte, len(bl1))
	news12 := make([][]byte, len(bl2))
	if len(bl1) > 0 {
		for i := 0; i < len(bl1); i++ {
			//var tmphandle []byte
			var buffer bytes.Buffer
			for j := 0; j < (len(opdivide)); j++ {
				start := opdivide[j][0]
				end := opdivide[j][1] + 1
				buffer.Write(bl1[i][start:end])
			}
			tmphandle := buffer.Bytes()
			news11 = append(news11, tmphandle)
		}
	}
	if len(bl2) > 0 {
		for i := 0; i < len(bl2); i++ {
			//var tmphandle []byte
			var buffer bytes.Buffer
			for j := 0; j < (len(objdivide)); j++ {
				start := objdivide[j][0]
				end := objdivide[j][1] + 1
				buffer.Write(bl2[i][start:end])
			}
			tmphandle := buffer.Bytes()
			news12 = append(news12, tmphandle)
		}
	}
	//log.Logf(0, "statevariables:  operationhandle len: %v, objecthandle len : %v", len(bl1), len(bl2))
	if len(news11) > 0 {
		sort.Slice(news11, func(i, j int) bool {
			flag := bytes.Compare(news11[i], news11[j])
			if flag < 0 {
				return true
			} else {
				return false
			}
		})
	}
	if len(news12) > 0 {
		sort.Slice(news12, func(i, j int) bool {
			flag := bytes.Compare(news12[i], news12[j])
			if flag < 0 {
				return true
			} else {
				return false
			}
		})
	}
	bl1_m := bytes.Join(news11, []byte(""))
	bl2_m := bytes.Join(news12, []byte(""))
	rawstate := append(bl1_m, bl2_m...)
	statevariables := hash.HashState(rawstate)
	return statevariables
}

func FromRawState(raw map[uint32][][]byte) State {
	//s := make(StateSlice, 1)
	tmpState := make(map[uint32][][]byte, 1)
	tmpState[1] = raw[1]
	tmpState[2] = raw[2]
	//s = append(s, tmpState)
	return tmpState

}

//func FromRawState(raw map[uint32][][]byte) MapStateSlice {
//	//s := make(StateSlice, 1)
//	tmpState := make(map[uint32][][]byte, 1)
//	tmpState[1] = raw[1]
//	tmpState[2] = raw[2]
//	//s = append(s, tmpState)
//	return tmpState
//
//}

func (s StateSlice) Merge(s1 State) {
	if s1.Empty() {
		return
	}
	s0 := s
	if s0 == nil {
		s0 = make(StateSlice, len(s1))
		s = s0
	} else {
		s = append(s, s1)
	}
}

func (s *MapStateSlice) Merge(s1 MapStateSlice) {
	//hashs1 := CalculateStateVariables(s1[1], s1[2])
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(map[hash.StateValues]int)
		*s = s0
	}

	for k := range s1 {
		if _, ok := s0[k]; ok {
			s0[k] += s1[k]
		} else {
			s0[k] = s1[k]
		}
		//log.Logf(0, " add %v to mapstateslice!, len MapStateSlices is ", k, s.Len())
	}
	*s = s0
}

//func (s State) Merge(s1 State) {
//
//}

func (s StateSlice) len() int {
	return len(s)
}

func (s State) Empty() bool {
	if len(s[1]) != 0 {
		return false
	}
	if len(s[2]) != 0 {
		return false
	}
	return true
}

func testByteSEq(bl1 [][]byte, bl2 [][]byte) bool {
	/* sort bl1 and bl2*/
	sort.Slice(bl1, func(i, j int) bool {
		flag := bytes.Compare(bl1[i], bl1[j])
		if flag < 0 {
			return true
		} else {
			return false
		}
	})
	sort.Slice(bl2, func(i, j int) bool {
		flag := bytes.Compare(bl1[i], bl1[j])
		if flag < 0 {
			return true
		} else {
			return false
		}
	})
	/* three conditions to check if two [][]byte are equal */
	if (bl1 == nil) != (bl2 == nil) {
		return false
	}

	if len(bl1) != len(bl2) {
		return false
	}
	for i := range bl1 {
		if !(bytes.Equal(bl1[i], bl2[2])) {
			return false
		}
	}
	return true
}

//func (s StateSlice) Diff(s1 State) State {
//	if s1.Empty() {
//		return nil
//	}
//	return s1
//}

func (s MapStateSlice) Diff(s1 MapStateSlice) MapStateSlice {
	if s1.Empty() {
		return nil
	}
	var res MapStateSlice
	for k := range s1 {
		if _, ok := s[k]; ok {
			continue
		}
		if res == nil {
			res = make(map[hash.StateValues]int)
		}
		res[k] = 1
	}
	return res
}

func (s *MapStateSlice) MergeMaxState(s1 MapStateSlice) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(map[hash.StateValues]int)
		*s = s0
	}
	for k := range s1 {
		if _, ok := s0[k]; ok {
			s0[k] = s0[k] + s1[k]
		} else {
			s0[k] = s1[k]
		}
	}
}

func (s *StateWeights) Merge(h1 hash.StateValues, s1 MapStateSlice) {
	if s1 == nil {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(map[hash.StateValues]float32)
		*s = s0
	}
	if tmp, ok := s1[h1]; ok {
		s0[h1] = 1 / (float32(tmp))
	} else {
		panic("state merge wrong! can not calculate weights")
	}
	if len(s0) != s1.Len() {
		panic("state weights is not equal to maxStates!")
	}
	*s = s0
}

/* divide state 4*/
func ConstructMapStateSlice(s1 State) MapStateSlice {

	res := make(map[hash.StateValues]int)
	res[CalculateStateVariables(s1[1], s1[2])] = 1
	return res
}

func ConstructMapDivideStateSlice(s1 State, handleDivision string) MapStateSlice {

	res := make(map[hash.StateValues]int)

	res[CalculateDivideStateVariables(s1[1], s1[2], handleDivision)] = 1
	return res
}
