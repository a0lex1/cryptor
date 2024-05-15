import string, random

def get_random_string(length, rng=None):
    if rng == None:
        rng = random.Random()
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(rng.choice(letters) for i in range(length))
    print("Random string of length", length, "is:", result_str)

