package api

// purgeProtectedMessage builds the per-item purge-protection message.
//
// The three resource mappers each hand-wrote this sentence with their own
// noun. One builder keeps them from drifting apart a word at a time.
func purgeProtectedMessage(noun string) string {
	return noun + " has purge protection enabled (directly or via its vault)"
}
