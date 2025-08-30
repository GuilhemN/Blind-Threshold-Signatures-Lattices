.PHONY: all clean

all: _proof_params_cffi.o

_proof_params_cffi.o: proof_params.h ../lazer/python/_lazer_cffi.o
	python3 ../lazer/python/params_cffi_build.py proof_params.h ../lazer

proof_params.h: proof_params.py
	cd ../lazer/scripts && sage lin-codegen.sage ../../proof/proof_params.py > ../../proof/proof_params.h

../lazer/python/_lazer_cffi.o:
	cd .. && make

clean:
	rm -rf __pycache__
	rm -f *.c *.o *.so
