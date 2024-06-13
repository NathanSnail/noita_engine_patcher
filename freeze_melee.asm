main:
	TEST AL, AL 
	MOV EAX, dword ptr[ESP + 0x44] 
	MOVSS XMM0, dword ptr[ESP + 0x18]
	JNZ player
	MOVSD XMM0, [EAX + 0x50]
	CVTPD2PS XMM0, XMM0
	MULSS XMM0, dword ptr[0x010514ec]
	JMP end
player:
	MULSS XMM0, dword ptr[0x011505ac]
end:
	NOP
