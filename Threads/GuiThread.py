import tkinter as tk
from tkinter import ttk
from tkinter import OptionMenu
from RSAKeysLibrary import *
from tkinterLibrary import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def GuiThread(threadID, name, socket, BUFFER, queue, publicKey, privateKey, otherPublicKey, sessionKey, rsaLocalKey):
    print('Starting B GUI Thread')
    #  -------
    #  TKINTER
    #  -------
    window = tk.Tk()
    window.title('Client ' + name)
    window.geometry('500x500')


    #  ---------------------
    #  GLOBALS FOR TKINTER #
    #  ---------------------
    pathStringVar = tk.StringVar()
    pathStringVar.set("path to the file we are sending")
    #  ---------------------


    #  --------------------
    #  TKINTER MAIN PROGRAM
    #  --------------------
    tk.Label(window, text='BSK Project').pack()
    tk.Label(window, text='Message:').pack()

    entry = tk.Entry(window)
    entry.pack()

    sendButton = tk.Button(window, text='send message', command=lambda: button_send_message(entry, socket))
    sendButton.pack()


    # RSA Messages (to delete in future) (won't be used for message exchange just session key)
    entry_encoded = tk.Entry(window)
    entry_encoded.pack()

    sendButtonEncoded = tk.Button(window, text='send message Encoded RSA', command=lambda: send_message_encoded_rsa(entry_encoded, socket, otherPublicKey, privateKey))
    sendButtonEncoded.pack()


    #  Ciphering MODE
    tk.Label(window, text='Choose ciphering mode:').pack()

    clicked = tk.StringVar()
    clicked.set("CBC")  # default value
    options = ['ECB', 'CBC']

    OptionMenu(window, clicked, *options).pack()

    cipheringMode = clicked.get()
    print(cipheringMode)


    #  CBC/ECB MESSAGE SENDING                 #@!#!## klucz SESYJNY DRUGIEJ STRONY MA BYC albo wspolny nie wlasny...
    entry_CBC = tk.Entry(window)
    entry_CBC.pack()

    tk_sendButtonCBC = tk.Button(window, text='send message Encoded CBC/ECB', command=lambda: send_message_encoded(clicked.get(), entry_CBC, sessionKey, socket)) #ZMIENIC SESSON KEY
    tk_sendButtonCBC.pack()

    #  ------------------INPUT-USER-FRIENDLY-PASSWORD--------------------
    tk.Label(window, text='Input your user-friendly password').pack()
    entryPassword = tk.Entry(window)
    entryPassword.pack()

    setPasswordButton = tk.Button(window, text='Set password Button (encrypt RSA keys with new key)', command=lambda: button_set_password(entryPassword, rsaLocalKey))
    setPasswordButton.pack()


    #  ------------------FILE-SENDING--------------------
    #  PROGRESS BAR
    tk.Label(window, text='Progress Bar:').pack()
    progressBar = ttk.Progressbar(window, orient='horizontal', mode='determinate', length=280)
    progressBar.pack()

    progressBarDescription = ttk.Label(window, text="Current Progress: 0%")
    progressBarDescription.pack()

    #  SENDING FILE
    tk.Label(window, textvariable=pathStringVar).pack()

    fileOpenButton = tk.Button(window, text='file dialog', command=lambda: button_open_file_function(pathStringVar))
    fileOpenButton.pack()

    fileSendButton = tk.Button(window, text='send file', command=lambda: button_send_file_function(socket, BUFFER, pathStringVar.get(), progressBar, progressBarDescription, window))
    fileSendButton.pack()


    # ------------------RECEIVING MESSAGES------------------
    #  Receiving Messages
    tk.Label(window, text='Received section:').pack()

    receivedContent = tk.StringVar()
    receivedContent.set('nothing')

    tk.Button(window, text='check', command=lambda: check_queue(queue, receivedContent)).pack()
    ttk.Label(window, textvariable=receivedContent).pack()

    #  end of LOOP
    window.mainloop()
