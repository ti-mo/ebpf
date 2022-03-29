package asm

// Metadata contains metadata about an instruction.
type Metadata struct {
	elems []metaElement
}

type metaElement struct {
	key, value interface{}
}

// find returns the metaElement with the given key along with
// its position in the Metadata slice.
func (m *Metadata) find(key interface{}) (int, *metaElement) {
	for i, e := range m.elems {
		if e.key == key {
			return i, &e
		}
	}
	return 0, nil
}

// delete deletes the metadata element with the given key, if present.
// The operation moves the last element of the slice into the slot that is
// to be deleted to avoid an additional slice reallocation.
func (m *Metadata) delete(key interface{}) {
	for i, e := range m.elems {
		if e.key == key {
			m.copy()
			m.elems[i] = m.elems[len(m.elems)-1]
			m.elems = m.elems[:len(m.elems)-1]
			return
		}
	}
}

// copy makes a copy of the elements contained in Metadata.
func (m *Metadata) copy() {
	ne := make([]metaElement, len(m.elems))
	copy(ne, m.elems)
	m.elems = ne
}

// Set a value to the metadata set.
//
// If value is nil, the key is removed. Avoids modifying old metadata by
// copying if necessary.
func (m *Metadata) Set(key, value interface{}) {
	if value == nil {
		// Caller wants to remove the metadata.
		m.delete(key)
		return
	}

	i, e := m.find(key)
	if e == nil {
		// No existing element, append it to the slice.
		m.copy()
		m.elems = append(m.elems, metaElement{key: key, value: value})
		return
	}
	if e.value == value {
		// Same value, nothing to do.
		return
	}

	// Different value, copy the metadata and update the element.
	m.copy()
	m.elems[i] = metaElement{key: key, value: value}
}

// Get a value from the metadata set.
//
// Returns nil if no value with the given key is present.
func (m *Metadata) Get(key interface{}) interface{} {
	if _, e := m.find(key); e != nil {
		return e.value
	}
	return nil
}
