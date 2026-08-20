import hashlib
import itertools
import string
import time
from multiprocessing import Process, Value, Manager
import os




def detect_hash(hash_value):
    length = len(hash_value)
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif length == 64:
        return "sha256"
    elif length == 128:
        return "sha512"
    else:
        return "unknown"

def hash_word(word, hash_type):
    if hash_type == "md5":
        return hashlib.md5(word.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(word.encode()).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(word.encode()).hexdigest()


def crack_dictionary(target_hash, hash_type, wordlist_path):
    attempts = 0
    start_time = time.time()
    with open(wordlist_path, 'r', encoding='latin-1') as f:
        for line in f:
            word = line.strip()
            attempts += 1
            if hash_word(word, hash_type) == target_hash:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                print(f"  Tried {attempts} words in {elapsed:.2f}s ({speed:.0f} hashes/sec)")
                return word
    elapsed = time.time() - start_time
    speed = attempts / elapsed if elapsed > 0 else 0
    print(f"  Tried {attempts} words in {elapsed:.2f}s ({speed:.0f} hashes/sec)")
    return None

def crack_bruteforce(target_hash,hash_type,max_lenght,charset):
    attempts = 0
    start_time = time.time()
    for lenght in range(1,max_lenght+1):
        for combo in itertools.product(charset,repeat=lenght):
            word=''.join(combo)
            attempts += 1
            if hash_word(word,hash_type) == target_hash :
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                print(f"  Tried {attempts} combinations in {elapsed:.2f}s ({speed:.0f} hashes/sec)")
                return word
    elapsed = time.time() - start_time
    speed = attempts / elapsed if elapsed > 0 else 0
    print(f"  Tried {attempts} combinations in {elapsed:.2f}s ({speed:.0f} hashes/sec)")
    return None

def generate_mutations(word):
    mutations = []
    mutations.append(word.capitalize())        
    mutations.append(word.upper())            
    mutations.append(word[::-1])               
    for i in range(10):
        mutations.append(word + str(i))        
    leet = word.replace('a', '@').replace('e', '3').replace('o', '0').replace('s', '$').replace('i', '1')
    mutations.append(leet)
    return mutations


def crack_rules(target_hash, hash_type, wordlist_path):
    attempts = 0
    start_time = time.time()
    with open(wordlist_path, 'r', encoding='latin-1') as f:
        for line in f:
            word = line.strip()
            attempts += 1
            if hash_word(word, hash_type) == target_hash:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                print(f"  Tried {attempts} words in {elapsed:.2f}s ({speed:.0f} hashes/sec)")
                return word
            for mutation in generate_mutations(word):
                attempts += 1
                if hash_word(mutation, hash_type) == target_hash:
                    elapsed = time.time() - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    print(f"  Tried {attempts} words in {elapsed:.2f}s ({speed:.0f} hashes/sec)")
                    return mutation
    elapsed = time.time() - start_time
    speed = attempts / elapsed if elapsed > 0 else 0
    print(f"  Tried {attempts} words in {elapsed:.2f}s ({speed:.0f} hashes/sec)")
    return None



def crack_chunk(chunk, target_hash, hash_type, found, result):
    for word in chunk:
        if found.value:       
            return
        if hash_word(word, hash_type) == target_hash:
            found.value = 1          
            result.append(word)      
            return

def crack_multiprocess(target_hash, hash_type, wordlist_path):
    
    with open(wordlist_path, 'r', encoding='latin-1') as f:
        words = [line.strip() for line in f]

    
    num_cores = os.cpu_count()
    chunk_size = len(words) // num_cores
    chunks = []
    for i in range(num_cores):
        start = i * chunk_size
        end = start + chunk_size if i < num_cores - 1 else len(words)
        chunks.append(words[start:end])

    
    found = Value('i', 0)
    manager = Manager()
    result = manager.list()

    
    processes = []
    for chunk in chunks:
        p = Process(target=crack_chunk, args=(chunk, target_hash, hash_type, found, result))
        processes.append(p)
        p.start()

    
    for p in processes:
        p.join()

    if result:
        return result[0]
    return None



if __name__ == "__main__" :
    print()
    print("HASH CRACKER PROGRAMME")
    print()
    print('1.Dictionary')
    print('2.Brute Force')
    print('3.Dictionnary+rules')
    print('4. Dictionary (Multiprocess)')

    choice = input("pick 1,2,3 or 4 :  ").strip()

    if choice == '1' :
        target = input("Enter hash to crack: ")
        hash_type = detect_hash(target)
        print(f"Detected hash type: {hash_type}")
        wordlist = input("Enter wordlist path: ")
        result = crack_dictionary(target, hash_type, wordlist)
        if result:
            print(f"CRACKED: {result}")
        else:
            print("Not found in wordlist")
    elif choice == '2':
        target = input("Enter hash to crack: ")
        hash_type = detect_hash(target)
        max_lenght = int(input("enter max lenght"))
        print(f"Detected hash type: {hash_type}")
        print("Choose charset:")
        print("1. Lowercase (a-z)")
        print("2. Lowercase + digits (a-z, 0-9)")
        print("3. Lowercase + uppercase (a-z, A-Z)")
        print("4. All (a-z, A-Z, 0-9, symbols)")
        charset_choice = input("Pick (1-4): ")
        if charset_choice == "1":
            charset = string.ascii_lowercase
        elif charset_choice == "2":
            charset = string.ascii_lowercase + string.digits
        elif charset_choice == "3":
            charset = string.ascii_lowercase + string.ascii_uppercase
        elif charset_choice == "4":
            charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        result = crack_bruteforce(target,hash_type,max_lenght,charset)
        if result:
            print(f"CRACKED: {result}")
        else:
            print("Not found")
    elif choice == '3':
        target = input("Enter hash to crack: ")
        hash_type = detect_hash(target)
        print(f"Detected hash type: {hash_type}")
        wordlist = input("Enter wordlist path: ")
        result = crack_rules(target, hash_type, wordlist)
        if result:
            print(f"CRACKED: {result}")
        else:
            print("Not found in wordlist or with mutations")
    elif choice == '4':
        target = input("Enter hash to crack: ")
        hash_type = detect_hash(target)
        print(f"Detected hash type: {hash_type}")
        wordlist = input("Enter wordlist path: ")
        start_time = time.time()
        result = crack_multiprocess(target, hash_type, wordlist)
        elapsed = time.time() - start_time
        if result:
            print(f"CRACKED: {result} (in {elapsed:.2f}s)")
        else:
            print("Not found in wordlist")
    else:
        print("invalide choice")
