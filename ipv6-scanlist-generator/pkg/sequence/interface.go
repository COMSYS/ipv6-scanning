package sequence

type Runs interface {
	Run(chan *StepInfo, chan *StepInfo)
}
