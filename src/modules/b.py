if __name__ == "__main__":
    with open("src/modules/a.txt") as f:
        lines = f.readlines()

    for lin in lines:
        print('"' + lin[2:].replace('\n', '') + '".to_string(),')