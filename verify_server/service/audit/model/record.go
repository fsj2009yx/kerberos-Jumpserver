package model

type Record struct {
	ID              uint64 `json:"id"`
	TS              int64  `json:"ts"`
	Time            string `json:"time"`
	Kind            string `json:"kind"`
	EventType       string `json:"event_type"`
	ClientID        string `json:"client_id,omitempty"`
	ClientAddr      string `json:"client_addr,omitempty"`
	TargetID        string `json:"target_id,omitempty"`
	TargetHost      string `json:"target_host,omitempty"`
	SSHUser         string `json:"ssh_user,omitempty"`
	PTYSessionID    uint32 `json:"pty_session_id,omitempty"`
	Direction       string `json:"direction,omitempty"`
	SeqNum          uint32 `json:"seq_num,omitempty"`
	MsgType         uint8  `json:"msg_type,omitempty"`
	PTYOp           uint8  `json:"pty_op,omitempty"`
	PTYEvent        uint8  `json:"pty_event,omitempty"`
	FrameType       string `json:"frame_type,omitempty"`
	FrameSize       int    `json:"frame_size,omitempty"`
	PayloadB64      string `json:"payload_b64,omitempty"`
	ExitCode        int32  `json:"exit_code,omitempty"`
	Result          string `json:"result"`
	ErrorCode       string `json:"error_code,omitempty"`
	RSAVerifyResult string `json:"rsa_verify_result,omitempty"`
	PrevHash        string `json:"prev_hash,omitempty"`
	RecordHash      string `json:"record_hash"`
}
