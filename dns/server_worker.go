package dns

import (
	"context"
	"fmt"
	"log/slog"
)

const defaultWorkerChannSize = 64

type workerJob struct {
	message   *Message
	responder func(*Message)
}

type worker struct {
	ctx      context.Context
	cancel   context.CancelFunc
	chann    chan workerJob
	cache    *workerCache
	resolver *workerResolver
}

func newWorker() *worker {
	chann := make(chan workerJob, defaultWorkerChannSize)
	ctx, cancel := context.WithCancel(context.Background())
	return &worker{
		ctx:      ctx,
		cancel:   cancel,
		chann:    chann,
		cache:    newWorkerCache(),
		resolver: newWorkerResolver(),
	}
}

func (w *worker) submit(job workerJob) {
	w.chann <- job
}

func (w *worker) run() {
	for {
		select {
		case <-w.ctx.Done():
			return
		case j := <-w.chann:
			response := w.process(j)
			j.responder(response)
		}
	}
}

func (w *worker) process(job workerJob) *Message {
	slog.Info("processing job")
	fmt.Println(job.message)

	msg := job.message

	if msg.Header.Response {
		slog.Warn("received message with response flag set")
		return createErrorResponseMessage(msg, RCODE_FORMAT_ERROR)
	}

	if msg.Header.Opcode != OPCODE_QUERY {
		slog.Warn("received message with opcode != OPCODE_QUERY", "opcode", msg.Header.Opcode)
		return createErrorResponseMessage(msg, RCODE_NOT_IMPLEMENTED)
	}

	if msg.Header.QuestionCount != 1 {
		slog.Warn("received message with incorrect number of questions", "questions", msg.Header.QuestionCount)
		return createErrorResponseMessage(msg, RCODE_FORMAT_ERROR)
	}

	if msg.Header.AnswerCount != 0 || msg.Header.AuthoritativeCount != 0 || msg.Header.AdditionalCount != 0 {
		slog.Warn("received message with resource records")
		return createErrorResponseMessage(msg, RCODE_FORMAT_ERROR)
	}

	question := msg.Questions[0]

	if question.Class != CLASS_IN {
		slog.Warn("received message with question class != CLASS_IN", "class", question.Class)
		return createErrorResponseMessage(msg, RCODE_NOT_IMPLEMENTED)
	}

	rrs := w.cache.get(question.Name, question.Type)
	if rrs == nil {
		resolvedRRs, err := w.resolver.Resolve(question.Name, question.Type)
		if err != nil {
			slog.Warn("failed to resolve name", "error", err, "name", question.Name)
			return createErrorResponseMessage(msg, RCODE_SERVER_FAILURE)
		}
		w.cache.put(question.Name, question.Type, resolvedRRs)
		rrs = resolvedRRs
	}

	response := &Message{}
	response.Header.Id = msg.Header.Id
	response.Header.Response = true
	response.Header.RecursionAvailable = true
	response.Header.RecursionDesired = msg.Header.RecursionDesired
	response.Header.ResponseCode = RCODE_NO_ERROR
	response.Header.QuestionCount = msg.Header.QuestionCount
	response.Header.AnswerCount = uint16(len(rrs))
	response.Questions = msg.Questions
	response.Answers = rrs
	fmt.Println("response")
	fmt.Println(response)

	return response
}
