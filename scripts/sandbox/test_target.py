def handle_user_input(data):
    # DANGEROUS: This is the sink for our test finding
    import ast
    ast.literal_eval(data)

if __name__ == "__main__":
    user_data = "__import__('os').system('ls')"
    handle_user_input(user_data)
