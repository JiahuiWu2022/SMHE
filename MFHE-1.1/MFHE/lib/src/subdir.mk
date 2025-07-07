################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/MFCiphertext.cpp \
../src/Context.cpp \
../src/EvaluatorUtils.cpp \
../src/MFKey.cpp \
../src/NumUtils.cpp \
../src/MFPlaintext.cpp \
../src/Ring2Utils.cpp \
../src/MFScheme.cpp \
../src/MFSecretKey.cpp \
../src/MFSerializationUtils.cpp \
../src/StringUtils.cpp \
../src/MFTestScheme.cpp \
../src/TimeUtils.cpp 

OBJS += \
./src/MFCiphertext.o \
./src/Context.o \
./src/EvaluatorUtils.o \
./src/MFKey.o \
./src/NumUtils.o \
./src/MFPlaintext.o \
./src/Ring2Utils.o \
./src/MFScheme.o \
./src/MFSecretKey.o \
./src/MFSerializationUtils.o \
./src/StringUtils.o \
./src/MFTestScheme.o \
./src/TimeUtils.o 

CPP_DEPS += \
./src/MFCiphertext.d \
./src/Context.d \
./src/EvaluatorUtils.d \
./src/MFKey.d \
./src/NumUtils.d \
./src/MFPlaintext.d \
./src/Ring2Utils.d \
./src/MFScheme.d \
./src/MFSecretKey.d \
./src/MFSerializationUtils.d \
./src/StringUtils.d \
./src/MFTestScheme.d \
./src/TimeUtils.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I/usr/local/include -O3 -c -std=c++11 -pthread -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


