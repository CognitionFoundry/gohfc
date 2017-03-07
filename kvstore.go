/*
Copyright Cognition Foundry / Conquex 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gohfc

import (
	"io/ioutil"
	"os"
	"encoding/json"
)

// KeyValueStore defines common interface for Key-Value storage
type KeyValueStore interface {
	// Get gets value associated with specific key.
	// Note that method returns 3 values. First is actual value, second is true if value is found in Key-Value store
	// so developer can distinguish if that value is non-existent or is just empty
	Get(key string) (string, bool, error)
	// Set sets key value pair in Key-Value storage
	Set(key string, value string) error
	// Delete deletes key-value pair from Key-Value storage
	Delete(key string) error
}

// MemoryKeyValue implements KeyValueStore interface and values are stored in map in memory.
// This storage is not permanent. When application terminates this values will be lost.
type MemoryKeyValue struct {
	data map[string]string
}

// FileKeyValue implements KeyValueStore interface and values are stored in file on file system.
// This storage is permanent but do not scale efficiently.
type FileKeyValue struct {
	data     map[string]string
	filePath string
}

// DummyKeyValue implements KeyValueStore interface and do not store any data.
type DummyKeyValue struct {
}

func (m *MemoryKeyValue) Get(key string) (string, bool, error) {
	_, ok := m.data[key]
	return m.data[key], ok, nil
}

func (m *MemoryKeyValue) Set(key string, value string) error {
	m.data[key] = value
	return nil
}

func (m *MemoryKeyValue) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (f *FileKeyValue) Get(key string) (string, bool, error) {
	_, ok := f.data[key]
	return f.data[key], ok, nil
}

func (f *FileKeyValue) Set(key string, value string) error {
	f.data[key] = value
	if err := f.saveData(); err != nil {
		return err
	}
	return nil
}

func (f *FileKeyValue) Delete(key string) error {
	delete(f.data, key)
	if err := f.saveData(); err != nil {
		return err
	}
	return nil
}

func (f *FileKeyValue) saveData() error {
	mapB, err := json.Marshal(f.data)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(f.filePath, mapB, 0666); err != nil {
		return err
	}
	return nil
}

func (f *FileKeyValue) loadData() error {
	data, err := ioutil.ReadFile(f.filePath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		f.data = make(map[string]string)
	} else if err := json.Unmarshal(data, &f.data); err != nil {
		return err
	}
	return nil
}

func (m *DummyKeyValue) Get(key string) (string, bool, error) {
	return "", false, nil
}

func (m *DummyKeyValue) Set(key string, value string) error {
	return nil
}

func (m *DummyKeyValue) Delete(key string) error {
	return nil
}

// NewMemoryKeyValue creates new memory Key-Value store
func NewMemoryKeyValue() *MemoryKeyValue {
	return &MemoryKeyValue{data: make(map[string]string)}
}

// NewFileKeyValue creates new file based Key-Value store
func NewFileKeyValue(path string) (*FileKeyValue, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			_, err = os.Create(path)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	f := &FileKeyValue{filePath: path}
	if err := f.loadData(); err != nil {
		return nil, err
	}
	return f, nil
}

// NewDummyKeyValue creates new dummy Key-Value store
func NewDummyKeyValue() *DummyKeyValue {
	return &DummyKeyValue{}
}
