from PIL import Image
img = Image.open('assets/shili.png')
icon_sizes = [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)]
img.save('assets/shili.ico', format='ICO', sizes=icon_sizes)