.PHONY: all clean

all: _proof_params_cffi.o

_proof_params_cffi.o: proof_params.h ../lazer/python/_lazer_cffi.o
	python3 ../lazer/python/params_cffi_build.py proof_params.h ../lazer

proof_params.h: proof_params.py
	cd ../lazer/scripts && sage lin-codegen.sage ../../proof_with_enc_to_the_sky/proof_params.py > ../../proof_with_enc_to_the_sky/proof_params.h

../lazer/python/_lazer_cffi.o:
	cd .. && make

clean:
	rm -rf __pycache__
	rm -f *.c *.o *.so
