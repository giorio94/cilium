// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"reflect"
)

// Overridable wraps a type, which is associated with a default implementation,
// defined through Defaulter[T], and possibly overridden if T is injected through
// Hive. This enables replacing default implementations from external modules,
// for instance, to introduce different functionalities.
type Overridable[T any] struct{ value T }

// Value returns the object wrapped by an Overridable[T].
func (o *Overridable[T]) Value() T { return o.value }

// Defaulter provides an Overridable[T], propagating T if injected through Hive,
// or constructing a default instance otherwise through the provided function.
func Defaulter[T any](defaulter func() T) func(defaulterIn[T]) Overridable[T] {
	return func(override defaulterIn[T]) Overridable[T] {
		if reflect.ValueOf(&override.Override).Elem().IsZero() {
			return Overridable[T]{value: defaulter()}
		}
		return Overridable[T]{value: override.Override}
	}
}

type defaulterIn[T any] struct {
	In
	Override T `optional:"true"`
}
