import time
import os
from RSAKeysLibrary import *


def ReceiveThread(threadID, name, socket, BUFFER, queue, publicKey, privateKey, sessionKey):
    print('Starting ' + name + ' receive thread')
    #  MAIN LOOP
    while True:
        TEST = socket.recv(BUFFER).decode("utf8")

        if TEST == "message":
            msg = socket.recv(BUFFER).decode("utf8")
            queue.put('You received a message:\n' + msg)

        if TEST == "file":

            SEPARATOR = "<SEPARATOR>"
            received = socket.recv(BUFFER).decode()
            filePath, fileSize = received.split(SEPARATOR)

            fileName = os.path.basename(filePath)
            fileSize = int(fileSize)  # fileSize in bytes

            # progress
            with open("./AcquiredFiles" + name + "/" + fileName, "wb") as f:
                receivedDataSize = 0

                startTime = time.time()

                while receivedDataSize < int(fileSize):
                    data = socket.recv(BUFFER)
                    if not data:
                        break  # no data means that full file has been received
                    f.write(data)
                    receivedDataSize += len(data)

                endTime = time.time()

                queue.put('You received a file:\nName: ' + fileName + '\nPath: ' + str(os.getcwd()) +
                          '\\AcquiredFiles' + name + "\\" + fileName + '\nSize: ' + str(fileSize / 1048576) +
                          ' MB\nTransfer time: ' + str(endTime - startTime) + ' s')

        if TEST == "message_encoded":
            print("we received a secret message from our spies my lord...")
            messageEncoded = socket.recv(BUFFER)
            print("message encrypted:")
            print(messageEncoded)
            print("message decrypted:")
            messageDecoded = decrypt(messageEncoded, privateKey)
            print(messageDecoded)
            queue.put("You received message encrypted with RSA:" + str(messageDecoded))

        if TEST == "message_encoded_cbc":
            print("CBC message has entered the castle")
            iVectorCBC = socket.recv(16)
            print("vector:" + str(iVectorCBC))
            print("koniec wektora")

            ciphertext = socket.recv(BUFFER)
            print("message encrypted:")
            print(ciphertext)
            print("message decrypted:")
            cipher = AES.new(sessionKey, AES.MODE_CBC, iVectorCBC)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            print(plaintext)
            queue.put("Message encoded with CBC with session key:" + str(plaintext))

        if TEST == "message_encoded_ecb":
            print("ECB message has entered the castle")
            ciphertext = socket.recv(BUFFER)
            print("message encrypted:")
            print(ciphertext)
            print("message decrypted:")
            cipher = AES.new(sessionKey, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            print(plaintext)
            queue.put("Message encoded with ECB with session key:" + str(plaintext))
