CFLAGS = -g -Wall -Wextra -Werror -fsanitize=address,leak,object-size,bounds-strict,undefined -fsanitize-address-use-after-scope
LDFLAGS = -lcurl -lcjson

all: mysh

mysh: mysh.o builtins.o commands.o variables.o io_helpers.o gpt.o
	gcc ${CFLAGS} -o $@ $^ ${LDFLAGS}

%.o: %.c builtins.h commands.h variables.h io_helpers.h gpt.h
	gcc ${CFLAGS} -c $< 

clean:
	rm *.o mysh
