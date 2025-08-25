package share

import "fmt"

type PerfLog struct {
        comm0To1     uint64 // bytes of communication between servers 0 and 1
	comm1To0     uint64

        comm1To2     uint64
	comm2To1     uint64

        comm2To0     uint64
	comm0To2     uint64
}

func (p *PerfLog) IncrementComm(q PerfLog) {
	p.comm0To1 += q.comm0To1
	p.comm1To0 += q.comm1To0
	p.comm1To2 += q.comm1To2
	p.comm2To1 += q.comm2To1
	p.comm2To0 += q.comm2To0
	p.comm0To2 += q.comm0To2
}

func (p *PerfLog) IdentifyDealer() uint {
        comm0 := p.comm0To1 + p.comm0To2
        comm1 := p.comm1To2 + p.comm1To0
        comm2 := p.comm2To0 + p.comm2To1

        if comm0 <= comm1 && comm0 <= comm2 {
		return 0
        }

        if comm1 <= comm0 && comm1 <= comm2 {
		return 1
        }

	return 2

}

// Increments the communication for the server that has communicated the least
func (p *PerfLog) IncrementCommDealer(comm uint64) {
	dealer := p.IdentifyDealer()

	if dealer == 0 {
		// server 0 is dealer
		p.comm0To1 += comm
		p.comm0To2 += comm
		return
	}

        if dealer == 1 {
                // server 1 is dealer
                p.comm1To0 += comm
                p.comm1To2 += comm
                return
        }

	p.comm2To0 += comm
	p.comm2To1 += comm
}

func (p *PerfLog) IncrementCommAllButDealer(dealer uint, comm uint64) {
	if dealer == 0 {
		p.comm1To2 += comm
		p.comm2To1 += comm
	} else if dealer == 1 {
		p.comm0To2 += comm
		p.comm2To0 += comm
	} else {
		p.comm0To1 += comm
		p.comm1To0 += comm
	}
}

func (p *PerfLog) IncrementCommThreeServers(comm uint64) {
	p.comm0To1 += comm
	p.comm1To2 += comm
	p.comm2To0 += comm
}

func (p *PerfLog) Print() {
	fmt.Println("Total communication:")
	fmt.Printf("   Server 0 to 1: %f KB = %f MB\n", float64(p.comm0To1)/1024, float64(p.comm0To1)/(1024*1024))
	fmt.Printf("   Server 0 to 2: %f KB = %f MB\n", float64(p.comm0To2)/1024, float64(p.comm0To2)/(1024*1024))
	fmt.Printf("   Server 1 to 0: %f KB = %f MB\n", float64(p.comm1To0)/1024, float64(p.comm1To0)/(1024*1024))
	fmt.Printf("   Server 1 to 2: %f KB = %f MB\n", float64(p.comm1To2)/1024, float64(p.comm1To2)/(1024*1024))
	fmt.Printf("   Server 2 to 0: %f KB = %f MB\n", float64(p.comm2To0)/1024, float64(p.comm2To0)/(1024*1024))
	fmt.Printf("   Server 2 to 1: %f KB = %f MB\n", float64(p.comm2To1)/1024, float64(p.comm2To1)/(1024*1024))

	total := p.comm0To1 + p.comm0To2
	total += p.comm1To0 + p.comm1To2
	total += p.comm2To0 + p.comm2To1
	fmt.Printf("   Total: %f KB = %f MB = %f GB\n", float64(total)/1024, float64(total)/(1024*1024), float64(total)/(1024*1024*1024))
}
