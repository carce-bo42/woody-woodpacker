NAME := woody

CFLAGS = #-Wall -Wextra -Werror
CFLAGS += -Wno-comment -Wno-unused-variable -Wno-unused-parameter
CFLAGS += -g3
###CFLAGS += -fsanitize=address

CC := gcc

SRC_FILES := woody.c

LIBFT_DIR := libft/

SRC_DIR := src
SRC := $(addprefix $(SRC_DIR)/, $(SRC_FILES))

OBJ_DIR := obj
OBJ := $(addprefix $(OBJ_DIR)/, $(SRC_FILES:.c=.o))

INC_DIR := include
INC_FLAGS = -I $(INC_DIR) -I $(LIBFT_DIR) -I.

.PHONY: all

all: $(OBJ_DIR) $(NAME)

$(OBJ_DIR):
	@[ ! -d $@ ] && mkdir -p $@

$(NAME): $(LIBFT_DIR)/libft.a
$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(INC_FLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $? -o $@

$(LIBFT_DIR)/libft.a:
	make -C $(LIBFT_DIR)

.PHONY: clean fclean re

clean:
	make clean -C $(LIBFT_DIR)
	rm -rf $(OBJ_DIR)/*.o

fclean: clean
	make fclean -C $(LIBFT_DIR)
	rm -f $(NAME)
	rm -rf $(OBJ_DIR)

re: fclean all
