//  Copyright 2013 Google Inc. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package bitmessage

import (
	"bytes"
	"reflect"
	"testing"
)

func TestSave(t *testing.T) {
	objects := newObjInventory()

	a := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

	objects.add(a, ipPort("127.0.0.1"))
	objects.add(a, ipPort("127.0.0.2"))
	buf := new(bytes.Buffer)
	if err := objects.save(buf); err != nil {
		t.Fatalf("object save error %v", err)
	}

	objectsNew := newObjInventory()
	if err := objectsNew.load(buf); err != nil {
		t.Fatalf("object load error %v", err)
	}
	if !reflect.DeepEqual(objects, objectsNew) {
		t.Fatalf("objects differ. Decoding failed?")
	}
}
