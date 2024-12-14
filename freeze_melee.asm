main:
	TEST AL, AL ; is player
	MOV EAX, dword ptr[ESP + 0x44] ; DamageModel
	MOVSS XMM0, dword ptr[ESP + 0x18] ; damage
	JNZ player
	MOVSD XMM0, [EAX + 0x50] ; max hp
	CVTPD2PS XMM0, XMM0
	MULSS XMM0, dword ptr[0x010514ec] ; 0.75
	JMP end
player:
	MULSS XMM0, dword ptr[0x011505ac] ; 5.0
end:
	NOP
