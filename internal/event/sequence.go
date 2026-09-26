package event

import "sort"

func sortedByTime(evs []*Event) bool {
	for i := 1; i < len(evs); i++ {
		if evs[i].Time.Before(evs[i-1].Time) {
			return false
		}
	}

	return true
}

func SeqWalk(events []Event, gap func(prev, cur Event, lost int), run func(cur Event, first bool)) int {
	count := map[string]int{}
	order := []string{}
	sequenced := 0

	for i := range events {
		if events[i].Seq == 0 {
			continue
		}
		sequenced++
		f := events[i].File
		if count[f] == 0 {
			order = append(order, f)
		}
		count[f]++
	}

	byFile := make(map[string][]*Event, len(order))
	for _, name := range order {
		byFile[name] = make([]*Event, 0, count[name])
	}

	for i := range events {
		if events[i].Seq != 0 {
			byFile[events[i].File] = append(
				byFile[events[i].File], &events[i])
		}
	}

	for _, name := range order {
		evs := byFile[name]
		if !sortedByTime(evs) {
			sort.SliceStable(evs, func(i, j int) bool {
				return evs[i].Time.Before(evs[j].Time)
			})
		}

		if run != nil {
			run(*evs[0], true)
		}

		for i := 1; i < len(evs); i++ {
			prev, cur := evs[i-1], evs[i]
			switch {
			case cur.Seq < prev.Seq:
				if run != nil {
					run(*cur, false)
				}
			case cur.Seq > prev.Seq+1:
				if gap != nil {
					gap(*prev, *cur, int(cur.Seq-prev.Seq-1))
				}
			}
		}
	}

	return sequenced
}
