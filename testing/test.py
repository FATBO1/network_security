


def check_duplicate(lst):
    for i in range(1, len(lst)):
        if lst[i] == lst[i - 1]:
            return True
    return False


print(check_duplicate([0,1,2,2]))

