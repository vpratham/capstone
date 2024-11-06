#run.py

#   MAIN FILE

from LoginWin import mainLogin
import cProfile

if __name__ == "__main__":
    cProfile.run('mainLogin()')