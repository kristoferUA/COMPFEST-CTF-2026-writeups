from sage.all import *

def jaas():
    p = int(input("Enter a prime number p: "))
    if not is_prime(p):
        raise ValueError()
    F = GF(p)

    R = F['x, y']; (x, y,) = R._first_ngens(2)
    expression = input("Enter a polynomial expression : ")
    allowed_chars = set("0123456789+-*/^xy ")
    if (not set(expression).issubset(allowed_chars) or not set("xy").issubset(set(expression))):
        raise ValueError()
    f = R(expression)

    E = Jacobian(f)
    print(E)

try:
    while True:
        print("1. try it out")
        print("2. send a bug report")
        choice = input("> ")

        if choice == "1":
            jaas()
            break
        if choice == "2":
            name = input("bug name: ")
            description = input("description: ")
            with open(name, "w") as report:
                report.write(description)
            print("report saved")
except Exception as e:
    print("Something went wrong.")
