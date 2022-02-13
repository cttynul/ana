from core import main
import sys

if __name__ == "__main__":
    try: input_file = sys.argv[1]
    except: input_file = None
    if input_file: main("auto", input_file)
    else: main("wizard")