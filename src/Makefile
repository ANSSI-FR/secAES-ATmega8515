###############################################################################
# Makefile for the project maskedAES
###############################################################################

#ARCH=at90s2323
#ARCH=at90s8515
#ARCH=at90s8535
#ARCH=atmega161
#ARCH=atmega163
ARCH=atmega8515

CC=avr-gcc -mmcu=$(ARCH)
AS=avr-as 
OBJCOPY=avr-objcopy
SIZE=avr-size

CFLAGS=-Wall -O0 -mcall-prologues
ASFLAGS=-Wall

DATE=`date +'%d%m%y-%H%M%S'`

BUILD_DIR = build
SOSSE_DIR = SOSSE
AESV1_DIR = Version1
AESV2_DIR = Version2

all: sosse aesv1 aesv2 eedata

clean: sosse_clean aesv1_clean aesv2_clean eedata_clean


###### SOSSE ##################################################################
# SOSSE OS objects compilation
SOSSE_SRC =  $(wildcard $(SOSSE_DIR)/*.c)
SOSSE_SRC += $(wildcard $(SOSSE_DIR)/*.S)
SOSSE_SRC += $(wildcard $(SOSSE_DIR)/*.s)

SOSSE_OBJ =  $(patsubst %.c, %.o, $(wildcard $(SOSSE_DIR)/*.c))
SOSSE_OBJ += $(patsubst %.S, %.o, $(wildcard $(SOSSE_DIR)/*.S))
SOSSE_OBJ += $(patsubst %.s, %.o, $(wildcard $(SOSSE_DIR)/*.s))

$(SOSSE_DIR)/%.o: $(SOSSE_DIR)/%.c
	$(CC) $(CFLAGS) -I$(SOSSE_DIR) -c $< -o $@

$(SOSSE_DIR)/%.o: $(SOSSE_DIR)/%.S
	$(CC) $(CFLAGS) -I$(SOSSE_DIR) -c $< -o $@

$(SOSSE_DIR)/%.o: $(SOSSE_DIR)/%.s
	$(AS) $(ASFLAGS) -I$(SOSSE_DIR) $< -o $@

sosse: $(SOSSE_OBJ)

sosse_clean:
	@rm -f $(SOSSE_DIR)/*.o
	@rm -f $(SOSSE_DIR)/*.map

###### AESV1 ##################################################################
# AESV1 objects compilation
AESV1_SRC =  $(wildcard $(AESV1_DIR)/*.c)
AESV1_SRC += $(wildcard $(AESV1_DIR)/*.S)

AESV1_OBJ =  $(patsubst %.c, %.o, $(wildcard $(AESV1_DIR)/*.c))
AESV1_OBJ += $(patsubst %.S, %.o, $(wildcard $(AESV1_DIR)/*.S))

AESV1_BIN = aesv1

$(AESV1_DIR)/%.o: $(AESV1_DIR)/%.c
	$(CC) $(CFLAGS) -I$(SOSSE_DIR) -I$(AESV1_DIR) -c $< -o $@

$(AESV1_DIR)/%.o: $(AESV1_DIR)/%.S
	$(CC) $(CFLAGS) -I$(SOSSE_DIR) -I$(AESV1_DIR) -c $< -o $@

aesv1: $(AESV1_OBJ) sosse
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wl,-Map,$(SOSSE_DIR)/sosse.map -o $(BUILD_DIR)/$(AESV1_BIN) $(filter-out $(SOSSE_DIR)/eedata.o, $(SOSSE_OBJ)) $(AESV1_OBJ)
	$(SIZE) $(BUILD_DIR)/$(AESV1_BIN)
	$(OBJCOPY) -O binary $(BUILD_DIR)/$(AESV1_BIN) $(BUILD_DIR)/$(AESV1_BIN).bin
	$(OBJCOPY) -O ihex $(BUILD_DIR)/$(AESV1_BIN) $(BUILD_DIR)/$(AESV1_BIN).hex
	$(OBJCOPY) -O ihex $(BUILD_DIR)/$(AESV1_BIN) $(BUILD_DIR)/$(AESV1_BIN)-$(DATE).hex
	@rm -f $(BUILD_DIR)/$(AESV1_BIN).bin $(BUILD_DIR)/$(AESV1_BIN).hex

aesv1_clean:
	@rm -f $(AESV1_DIR)/*.o
	@rm -f $(BUILD_DIR)/$(AESV1_BIN)*

###### AESV2 ##################################################################
# AESV2 objects compilation
AESV2_SRC =  $(wildcard $(AESV2_DIR)/*.c)
AESV2_SRC += $(wildcard $(AESV2_DIR)/*.S)

AESV2_OBJ =  $(patsubst %.c, %.o, $(wildcard $(AESV2_DIR)/*.c))
AESV2_OBJ += $(patsubst %.S, %.o, $(wildcard $(AESV2_DIR)/*.S))

AESV2_BIN = aesv2

$(AESV2_DIR)/%.o: $(AESV2_DIR)/%.c
	$(CC) $(CFLAGS) -I$(SOSSE_DIR) -I$(AESV2_DIR) -c $< -o $@

$(AESV2_DIR)/%.o: $(AESV2_DIR)/%.S
	$(CC) $(CFLAGS) -I$(SOSSE_DIR) -I$(AESV2_DIR) -c $< -o $@

aesv2: $(AESV2_OBJ) sosse
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wl,-Map,$(SOSSE_DIR)/sosse.map -o $(BUILD_DIR)/$(AESV2_BIN) $(filter-out $(SOSSE_DIR)/eedata.o, $(SOSSE_OBJ)) $(AESV2_OBJ)
	$(SIZE) $(BUILD_DIR)/$(AESV2_BIN)
	$(OBJCOPY) -O binary $(BUILD_DIR)/$(AESV2_BIN) $(BUILD_DIR)/$(AESV2_BIN).bin
	$(OBJCOPY) -O ihex $(BUILD_DIR)/$(AESV2_BIN) $(BUILD_DIR)/$(AESV2_BIN).hex
	$(OBJCOPY) -O ihex $(BUILD_DIR)/$(AESV2_BIN) $(BUILD_DIR)/$(AESV2_BIN)-$(DATE).hex
	@rm -f $(BUILD_DIR)/$(AESV2_BIN).bin $(BUILD_DIR)/$(AESV2_BIN).hex

aesv2_clean:
	@rm -f $(AESV2_DIR)/*.o
	@rm -f $(BUILD_DIR)/$(AESV2_BIN)*

###### EEDATA #################################################################
EEDATA_SRC = $(SOSSE_DIR)/eedata.S
EEDATA_BIN = eedata

eedata:
	$(CC) $(ASFLAGS) -c -o $(BUILD_DIR)/$(EEDATA_BIN) -I$(SOSSE_DIR) -DDAY=0x`date +%d` -DMONTH=0x`date +%m` -DYEAR=0x`date +%y` $(EEDATA_SRC)
	$(OBJCOPY) -O binary $(BUILD_DIR)/$(EEDATA_BIN) $(BUILD_DIR)/$(EEDATA_BIN).bin
	$(OBJCOPY) -O ihex $(BUILD_DIR)/$(EEDATA_BIN) $(BUILD_DIR)/$(EEDATA_BIN).hex
	$(OBJCOPY) -O ihex $(BUILD_DIR)/$(EEDATA_BIN) $(BUILD_DIR)/$(EEDATA_BIN)-$(DATE).hex
	@rm -f $(BUILD_DIR)/$(EEDATA_BIN).bin $(BUILD_DIR)/$(EEDATA_BIN).hex

eedata_clean:
	@rm -f $(BUILD_DIR)/$(EEDATA_BIN)*
