from PIL import Image, ImageDraw
import os

def create_icon():
    # 创建不同尺寸的图标
    sizes = [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)]
    images = []
    
    for size in sizes:
        # 创建新图像，使用RGBA模式支持透明度
        img = Image.new('RGBA', size, (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # 计算缩放比例
        scale = size[0] / 256
        
        # 绘制圆形背景
        circle_radius = int(120 * scale)
        center_x = size[0] // 2
        center_y = size[1] // 2
        draw.ellipse([
            center_x - circle_radius,
            center_y - circle_radius,
            center_x + circle_radius,
            center_y + circle_radius
        ], fill=(41, 128, 185, 255))  # Cursor蓝色
        
        # 绘制Cursor窗口形状
        window_width = int(160 * scale)
        window_height = int(120 * scale)
        x = center_x - window_width // 2
        y = center_y - window_height // 2
        
        # 绘制窗口背景
        draw.rectangle([x, y, x + window_width, y + window_height], 
                      fill=(255, 255, 255, 255))  # 白色背景
        
        # 绘制窗口标题栏
        title_height = int(20 * scale)
        draw.rectangle([x, y, x + window_width, y + title_height], 
                      fill=(52, 152, 219, 255))  # 浅蓝色
        
        # 绘制验证符号（对勾）
        check_size = int(60 * scale)
        check_x = x + (window_width - check_size) // 2
        check_y = y + title_height + (window_height - title_height - check_size) // 2
        
        # 绘制对勾
        points = [
            (check_x + check_size * 0.2, check_y + check_size * 0.5),
            (check_x + check_size * 0.4, check_y + check_size * 0.7),
            (check_x + check_size * 0.8, check_y + check_size * 0.3)
        ]
        draw.line(points, fill=(41, 128, 185, 255), width=int(6 * scale))
        
        # 转换为RGB模式（ICO文件不支持RGBA）
        img = img.convert('RGB')
        images.append(img)
    
    # 保存为ICO文件
    if not os.path.exists('assets'):
        os.makedirs('assets')
    
    # 使用第一个图像保存所有尺寸
    images[0].save('assets/shili.ico', format='ICO', sizes=sizes)

if __name__ == '__main__':
    create_icon() 