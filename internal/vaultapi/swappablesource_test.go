package vaultapi

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubTokenSource struct {
	token string
	err   error
}

func (s stubTokenSource) Token(ctx context.Context) (string, error) { return s.token, s.err }

func TestSwappableSource_DelegatesToInitial(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{token: "one"})
	tok, err := s.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "one", tok)
}

func TestSwappableSource_SetSwitchesImmediately(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{token: "one"})
	s.Set(stubTokenSource{token: "two"})

	tok, err := s.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "two", tok)
}

func TestSwappableSource_PropagatesCurrentSourceError(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{err: errors.New("boom")})
	_, err := s.Token(context.Background())
	require.ErrorContains(t, err, "boom")
}

func TestSwappableSource_ConcurrentSetAndTokenIsRace(t *testing.T) {
	s := NewSwappableSource(stubTokenSource{token: "initial"})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			s.Set(stubTokenSource{token: "swapped"})
		}(i)
		go func() {
			defer wg.Done()
			_, _ = s.Token(context.Background())
		}()
	}
	wg.Wait()

	tok, err := s.Token(context.Background())
	require.NoError(t, err)
	require.Equal(t, "swapped", tok)
}

func TestSwappableSource_SatisfiesTokenSource(t *testing.T) {
	var _ TokenSource = (*SwappableSource)(nil)
}
