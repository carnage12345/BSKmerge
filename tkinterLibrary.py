from tkinter import filedialog
from tkinter.messagebox import showinfo
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from RSAKeysLibrary import encrypt, decrypt, sign_sha1, verify_sha1
import os


def button_send_message(entry, client):
    message = entry.get()
    print(message)
    client.send("message".encode("utf8"))
    client.send(message.encode("utf8"))


def send_message_encoded_rsa(tk_entry_encoded, client, otherPublicKey, privateKey): # OTHER SIDES PUBLIC KEY!!!!
    message = tk_entry_encoded.get()
    print(message)

    ciphertext = encrypt(message, otherPublicKey)
    signature = sign_sha1(message, privateKey)

    client.send("message_encoded".encode("utf8"))
    client.send(ciphertext)


def send_message_encoded_cbc(tk_entry_CBC, sessionKey, client):   #  OTHER SIDES SESSION KEY!!! and even better 1 session key for both sides, czemu do jasnej cholery jest pad podany na wejsciu
    message = tk_entry_CBC.get()
    print(message)

    cipherCBC = AES.new(sessionKey, AES.MODE_CBC)
    iVectorCBC = cipherCBC.iv
    ciphertextCBC = cipherCBC.encrypt(pad(message.encode("utf8"), AES.block_size))

    print(ciphertextCBC)

    client.send("message_encoded_cbc".encode("utf8"))
    client.send(iVectorCBC)  # czy wektor powinien byc zakodowany? -nie, nie powinien
    print("vector wysłany: " + str(iVectorCBC))
    client.send(ciphertextCBC)
    print("ciphertext wysłany: " + str(ciphertextCBC))



def send_message_encoded_ecb(tk_entry_CBC, sessionKey, client): ### POPRAWIC WSZYSTKO
    message = tk_entry_CBC.get()
    print(message)
    cipherECB = AES.new(sessionKey, AES.MODE_ECB)

    ciphertextECB = cipherECB.encrypt(pad(message.encode("utf8"), AES.block_size))
    print(ciphertextECB)

    client.send("message_encoded_ecb".encode("utf8"))
    client.send(ciphertextECB)


def send_message_encoded(mode, tk_entry_CBC, sessionKey, client):
    if mode == 'CBC':
        send_message_encoded_cbc(tk_entry_CBC, sessionKey, client)
    elif mode == 'ECB':
        send_message_encoded_ecb(tk_entry_CBC, sessionKey, client)




def button_open_file_function(pathStringVar):
    path = filedialog.askopenfilename(title="BSK - which file to open?",
                                      filetypes=(("all files", "*.*"),
                                                 ("txt files", "*.txt"),
                                                 ("png files", "*.png"),
                                                 ("pdf files", "*.pdf"),
                                                 ("avi files", "*.avi"),
                                                 ("jpg files", "*.jpg")))
    print(path)
    pathStringVar.set(path)


def button_send_file_function(client, BUFFER, path, pb, pbValue, window):
    client.send("file".encode("utf8"))

    SEPARATOR = "<SEPARATOR>"
    # filePath = file_path_test
    filePath = path
    fileSize = os.path.getsize(filePath)

    client.send(f"{filePath}{SEPARATOR}{fileSize}".encode())

    print(filePath)

    print(str(fileSize), ' B, ', str(fileSize / 1024), ' KB, ', str(fileSize / 1048576), ' MB')
    with open(filePath, "rb") as f:
        sendDataSize = 0
        startTime = time.time()
        while sendDataSize < fileSize:
            data = f.read(BUFFER)
            if not data:
                break
            client.sendall(data)
            sendDataSize += len(data)
            # print(str(sendDataSize * 100 / fileSize) + ' %')
            # progress.update(len(bytes_read))
            # progress_bar(pb, pbValue, sendDataSize, fileSize)

            # Progress Bar
            if pb['value'] < 100:
                pb['value'] = int((sendDataSize * 100) / fileSize)
                pbValue['text'] = f"Current Progress: {pb['value']}%"  # update_progress_label(pb)

            window.update()

    endTime = time.time()
    showinfo(message='The progress completed!')
    pb['value'] = 0
    pbValue['text'] = f"Current Progress: 0%"
    print("File transfer complete:", endTime - startTime, " s")




def check_queue(queue, control):
    if queue.empty():
        print('queue is empty')
        control.set('nothing')
    else:
        print('queue is not empty')
        control.set(queue.get())



