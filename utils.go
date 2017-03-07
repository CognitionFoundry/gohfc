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
	"crypto/rand"
	"path/filepath"
	"os"
	"archive/tar"
	"strings"
	"io"
	"bytes"
	"compress/gzip"
)

// toChaincodeArgs converts arguments string array to binary multi-dimension slice for protobuffers
func toChaincodeArgs(args []string) [][]byte {
	bargs := make([][]byte, len(args))
	for i, arg := range args {
		bargs[i] = []byte(arg)
	}
	return bargs
}

// GenerateRandomBytes generates random bytes using crypto/random
func GenerateRandomBytes(len int) ([]byte, error) {
	bytes := make([]byte, len)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// gzipGoSource compresses go chaincode. This function also fixes folders' structure, files and folders permissions
func gzipGoSource(source string) ([]byte, error) {

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	_, err := os.Stat(source)
	if err != nil {
		Logger.Errorf("Error reading src: %s", err)
		return nil, err
	}
	baseDir := "/src"
	err = filepath.Walk(source,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}
			header.Mode = 0100000
			if baseDir != "" {
				header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))

			}
			if header.Name == baseDir {
				return nil
			}

			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tw, file)
			return err
		})
	if err != nil {
		Logger.Errorf("Error write tar file: %s", err)
		tw.Close()
		return nil, err
	}
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, err = zw.Write(buf.Bytes())
	if err != nil {
		Logger.Errorf("Error write gz file: %s", err)
		return nil, err
	}
	tw.Close()
	zw.Close()
	if err != nil {
		Logger.Errorf("Error write gz file: %s", err)
		return nil, err
	}
	return gzBuf.Bytes(), nil
}
