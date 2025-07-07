# This sample should be run after make libMFHE.a file in lib folder

# # All Target
# all: clean MFHE run

# # Tool invocations
# MFHE:
# 	@echo 'Building target: $@'
# 	@echo 'Invoking: GCC C++ Linker'
# 	g++ -L/usr/local/lib -o "MFHE" ../lib/libMFHE.a run.cpp -I/../src -lgmp -lntl -lm -O2 -std=c++11
# 	@echo 'Finished building target: $@'
# 	@echo ' '

# # Other Targets
# clean:
# 	rm -rf MFHE

# run:
# 	./MFHE

#---------------------------------------------------
# All Target
all: clean TestMFHE

# Tool invocations
TestMFHE:
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	g++ run.cpp -o TestMFHE -L/usr/local/lib ../lib/libMFHE.a -lntl -lgmp -lm -std=c++11 -O2 -I/../src -pthread
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	rm -rf TestMFHE