// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"io"
	"sync"

	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/ssb"
)

type FakeBlobStore struct {
	ChangesStub        func() luigi.Broadcast
	changesMutex       sync.RWMutex
	changesArgsForCall []struct {
	}
	changesReturns struct {
		result1 luigi.Broadcast
	}
	changesReturnsOnCall map[int]struct {
		result1 luigi.Broadcast
	}
	DeleteStub        func(*ssb.BlobRef) error
	deleteMutex       sync.RWMutex
	deleteArgsForCall []struct {
		arg1 *ssb.BlobRef
	}
	deleteReturns struct {
		result1 error
	}
	deleteReturnsOnCall map[int]struct {
		result1 error
	}
	GetStub        func(*ssb.BlobRef) (io.Reader, error)
	getMutex       sync.RWMutex
	getArgsForCall []struct {
		arg1 *ssb.BlobRef
	}
	getReturns struct {
		result1 io.Reader
		result2 error
	}
	getReturnsOnCall map[int]struct {
		result1 io.Reader
		result2 error
	}
	ListStub        func() luigi.Source
	listMutex       sync.RWMutex
	listArgsForCall []struct {
	}
	listReturns struct {
		result1 luigi.Source
	}
	listReturnsOnCall map[int]struct {
		result1 luigi.Source
	}
	PutStub        func(io.Reader) (*ssb.BlobRef, error)
	putMutex       sync.RWMutex
	putArgsForCall []struct {
		arg1 io.Reader
	}
	putReturns struct {
		result1 *ssb.BlobRef
		result2 error
	}
	putReturnsOnCall map[int]struct {
		result1 *ssb.BlobRef
		result2 error
	}
	SizeStub        func(*ssb.BlobRef) (int64, error)
	sizeMutex       sync.RWMutex
	sizeArgsForCall []struct {
		arg1 *ssb.BlobRef
	}
	sizeReturns struct {
		result1 int64
		result2 error
	}
	sizeReturnsOnCall map[int]struct {
		result1 int64
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeBlobStore) Changes() luigi.Broadcast {
	fake.changesMutex.Lock()
	ret, specificReturn := fake.changesReturnsOnCall[len(fake.changesArgsForCall)]
	fake.changesArgsForCall = append(fake.changesArgsForCall, struct {
	}{})
	fake.recordInvocation("Changes", []interface{}{})
	fake.changesMutex.Unlock()
	if fake.ChangesStub != nil {
		return fake.ChangesStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.changesReturns
	return fakeReturns.result1
}

func (fake *FakeBlobStore) ChangesCallCount() int {
	fake.changesMutex.RLock()
	defer fake.changesMutex.RUnlock()
	return len(fake.changesArgsForCall)
}

func (fake *FakeBlobStore) ChangesCalls(stub func() luigi.Broadcast) {
	fake.changesMutex.Lock()
	defer fake.changesMutex.Unlock()
	fake.ChangesStub = stub
}

func (fake *FakeBlobStore) ChangesReturns(result1 luigi.Broadcast) {
	fake.changesMutex.Lock()
	defer fake.changesMutex.Unlock()
	fake.ChangesStub = nil
	fake.changesReturns = struct {
		result1 luigi.Broadcast
	}{result1}
}

func (fake *FakeBlobStore) ChangesReturnsOnCall(i int, result1 luigi.Broadcast) {
	fake.changesMutex.Lock()
	defer fake.changesMutex.Unlock()
	fake.ChangesStub = nil
	if fake.changesReturnsOnCall == nil {
		fake.changesReturnsOnCall = make(map[int]struct {
			result1 luigi.Broadcast
		})
	}
	fake.changesReturnsOnCall[i] = struct {
		result1 luigi.Broadcast
	}{result1}
}

func (fake *FakeBlobStore) Delete(arg1 *ssb.BlobRef) error {
	fake.deleteMutex.Lock()
	ret, specificReturn := fake.deleteReturnsOnCall[len(fake.deleteArgsForCall)]
	fake.deleteArgsForCall = append(fake.deleteArgsForCall, struct {
		arg1 *ssb.BlobRef
	}{arg1})
	fake.recordInvocation("Delete", []interface{}{arg1})
	fake.deleteMutex.Unlock()
	if fake.DeleteStub != nil {
		return fake.DeleteStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.deleteReturns
	return fakeReturns.result1
}

func (fake *FakeBlobStore) DeleteCallCount() int {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return len(fake.deleteArgsForCall)
}

func (fake *FakeBlobStore) DeleteCalls(stub func(*ssb.BlobRef) error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = stub
}

func (fake *FakeBlobStore) DeleteArgsForCall(i int) *ssb.BlobRef {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	argsForCall := fake.deleteArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeBlobStore) DeleteReturns(result1 error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = nil
	fake.deleteReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeBlobStore) DeleteReturnsOnCall(i int, result1 error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = nil
	if fake.deleteReturnsOnCall == nil {
		fake.deleteReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.deleteReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeBlobStore) Get(arg1 *ssb.BlobRef) (io.Reader, error) {
	fake.getMutex.Lock()
	ret, specificReturn := fake.getReturnsOnCall[len(fake.getArgsForCall)]
	fake.getArgsForCall = append(fake.getArgsForCall, struct {
		arg1 *ssb.BlobRef
	}{arg1})
	fake.recordInvocation("Get", []interface{}{arg1})
	fake.getMutex.Unlock()
	if fake.GetStub != nil {
		return fake.GetStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeBlobStore) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *FakeBlobStore) GetCalls(stub func(*ssb.BlobRef) (io.Reader, error)) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = stub
}

func (fake *FakeBlobStore) GetArgsForCall(i int) *ssb.BlobRef {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	argsForCall := fake.getArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeBlobStore) GetReturns(result1 io.Reader, result2 error) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 io.Reader
		result2 error
	}{result1, result2}
}

func (fake *FakeBlobStore) GetReturnsOnCall(i int, result1 io.Reader, result2 error) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	if fake.getReturnsOnCall == nil {
		fake.getReturnsOnCall = make(map[int]struct {
			result1 io.Reader
			result2 error
		})
	}
	fake.getReturnsOnCall[i] = struct {
		result1 io.Reader
		result2 error
	}{result1, result2}
}

func (fake *FakeBlobStore) List() luigi.Source {
	fake.listMutex.Lock()
	ret, specificReturn := fake.listReturnsOnCall[len(fake.listArgsForCall)]
	fake.listArgsForCall = append(fake.listArgsForCall, struct {
	}{})
	fake.recordInvocation("List", []interface{}{})
	fake.listMutex.Unlock()
	if fake.ListStub != nil {
		return fake.ListStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.listReturns
	return fakeReturns.result1
}

func (fake *FakeBlobStore) ListCallCount() int {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return len(fake.listArgsForCall)
}

func (fake *FakeBlobStore) ListCalls(stub func() luigi.Source) {
	fake.listMutex.Lock()
	defer fake.listMutex.Unlock()
	fake.ListStub = stub
}

func (fake *FakeBlobStore) ListReturns(result1 luigi.Source) {
	fake.listMutex.Lock()
	defer fake.listMutex.Unlock()
	fake.ListStub = nil
	fake.listReturns = struct {
		result1 luigi.Source
	}{result1}
}

func (fake *FakeBlobStore) ListReturnsOnCall(i int, result1 luigi.Source) {
	fake.listMutex.Lock()
	defer fake.listMutex.Unlock()
	fake.ListStub = nil
	if fake.listReturnsOnCall == nil {
		fake.listReturnsOnCall = make(map[int]struct {
			result1 luigi.Source
		})
	}
	fake.listReturnsOnCall[i] = struct {
		result1 luigi.Source
	}{result1}
}

func (fake *FakeBlobStore) Put(arg1 io.Reader) (*ssb.BlobRef, error) {
	fake.putMutex.Lock()
	ret, specificReturn := fake.putReturnsOnCall[len(fake.putArgsForCall)]
	fake.putArgsForCall = append(fake.putArgsForCall, struct {
		arg1 io.Reader
	}{arg1})
	fake.recordInvocation("Put", []interface{}{arg1})
	fake.putMutex.Unlock()
	if fake.PutStub != nil {
		return fake.PutStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.putReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeBlobStore) PutCallCount() int {
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	return len(fake.putArgsForCall)
}

func (fake *FakeBlobStore) PutCalls(stub func(io.Reader) (*ssb.BlobRef, error)) {
	fake.putMutex.Lock()
	defer fake.putMutex.Unlock()
	fake.PutStub = stub
}

func (fake *FakeBlobStore) PutArgsForCall(i int) io.Reader {
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	argsForCall := fake.putArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeBlobStore) PutReturns(result1 *ssb.BlobRef, result2 error) {
	fake.putMutex.Lock()
	defer fake.putMutex.Unlock()
	fake.PutStub = nil
	fake.putReturns = struct {
		result1 *ssb.BlobRef
		result2 error
	}{result1, result2}
}

func (fake *FakeBlobStore) PutReturnsOnCall(i int, result1 *ssb.BlobRef, result2 error) {
	fake.putMutex.Lock()
	defer fake.putMutex.Unlock()
	fake.PutStub = nil
	if fake.putReturnsOnCall == nil {
		fake.putReturnsOnCall = make(map[int]struct {
			result1 *ssb.BlobRef
			result2 error
		})
	}
	fake.putReturnsOnCall[i] = struct {
		result1 *ssb.BlobRef
		result2 error
	}{result1, result2}
}

func (fake *FakeBlobStore) Size(arg1 *ssb.BlobRef) (int64, error) {
	fake.sizeMutex.Lock()
	ret, specificReturn := fake.sizeReturnsOnCall[len(fake.sizeArgsForCall)]
	fake.sizeArgsForCall = append(fake.sizeArgsForCall, struct {
		arg1 *ssb.BlobRef
	}{arg1})
	fake.recordInvocation("Size", []interface{}{arg1})
	fake.sizeMutex.Unlock()
	if fake.SizeStub != nil {
		return fake.SizeStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.sizeReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeBlobStore) SizeCallCount() int {
	fake.sizeMutex.RLock()
	defer fake.sizeMutex.RUnlock()
	return len(fake.sizeArgsForCall)
}

func (fake *FakeBlobStore) SizeCalls(stub func(*ssb.BlobRef) (int64, error)) {
	fake.sizeMutex.Lock()
	defer fake.sizeMutex.Unlock()
	fake.SizeStub = stub
}

func (fake *FakeBlobStore) SizeArgsForCall(i int) *ssb.BlobRef {
	fake.sizeMutex.RLock()
	defer fake.sizeMutex.RUnlock()
	argsForCall := fake.sizeArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeBlobStore) SizeReturns(result1 int64, result2 error) {
	fake.sizeMutex.Lock()
	defer fake.sizeMutex.Unlock()
	fake.SizeStub = nil
	fake.sizeReturns = struct {
		result1 int64
		result2 error
	}{result1, result2}
}

func (fake *FakeBlobStore) SizeReturnsOnCall(i int, result1 int64, result2 error) {
	fake.sizeMutex.Lock()
	defer fake.sizeMutex.Unlock()
	fake.SizeStub = nil
	if fake.sizeReturnsOnCall == nil {
		fake.sizeReturnsOnCall = make(map[int]struct {
			result1 int64
			result2 error
		})
	}
	fake.sizeReturnsOnCall[i] = struct {
		result1 int64
		result2 error
	}{result1, result2}
}

func (fake *FakeBlobStore) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.changesMutex.RLock()
	defer fake.changesMutex.RUnlock()
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	fake.putMutex.RLock()
	defer fake.putMutex.RUnlock()
	fake.sizeMutex.RLock()
	defer fake.sizeMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeBlobStore) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ ssb.BlobStore = new(FakeBlobStore)
