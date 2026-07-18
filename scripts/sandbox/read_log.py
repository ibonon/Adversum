try:
    print("Trying UTF-16...")
    with open(r"F:\Adversum\adversum\core\build_log_clean.txt", "r", encoding="utf-16") as f:
        for line in f:
            if "error" in line.lower() or "warning" in line.lower() or "-->" in line:
                print(line.strip())
except Exception as e:
    print(f"Error reading utf-16: {e}")
    try:
        print("Trying UTF-8...")
        with open(r"F:\Adversum\adversum\core\build_log_clean.txt", "r", encoding="utf-8") as f:
            for line in f:
                if "error" in line.lower() or "warning" in line.lower() or "-->" in line:
                    print(line.strip())
    except Exception as e2:
        print(f"Error reading utf-8: {e2}")
