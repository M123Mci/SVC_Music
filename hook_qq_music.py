import frida
import os
from pathlib import Path
import logging

def decrypt_music_files():
    """解密QQ音乐文件"""
    try:
        # 连接到QQ音乐进程
        session = frida.attach("QQMusic.exe")
        
        # 加载解密脚本
        script_path = os.path.join(os.path.dirname(__file__), "decrypt_script.js")
        with open(script_path) as f:
            script_code = f.read()
        script = session.create_script(script_code)
        script.load()
        
        # 获取输入目录路径
        input_dir = Path("input/music")
        output_dir = Path("middle/Music")
        
        if not input_dir.exists():
            print("输入目录不存在")
            return
            
        # 确保输出目录存在
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 首先检查是否有需要解密的文件
        need_decrypt = False
        for file_path in input_dir.glob("*"):
            if (file_path.suffix.lower() in [".mflac", ".mgg"] and 
                not (output_dir / f"{file_path.stem}{file_path.suffix.lower().replace('mflac', 'flac').replace('mgg', 'ogg')}").exists()):
                need_decrypt = True
                break
        
        if not need_decrypt:
            print("没有需要解密的文件")
            return
            
        # 有需要解密的文件时才进行解密操作
        for file_path in input_dir.glob("*"):
            if file_path.suffix.lower() in [".mflac", ".mgg"]:
                print(f"解密文件: {file_path.name}")
                
                # 修改文件扩展名
                new_ext = file_path.suffix.lower().replace("mflac", "flac").replace("mgg", "ogg")
                output_path = output_dir / f"{file_path.stem}{new_ext}"
                
                if output_path.exists():
                    print(f"文件已存在，跳过: {output_path}")
                    continue
                
                try:
                    # 调用解密函数
                    script.exports_sync.decrypt(str(file_path.absolute()), str(output_path))
                    print(f"解密成功: {output_path}")
                except Exception as e:
                    print(f"解密失败: {file_path.name}, 错误: {str(e)}")
                    
    except Exception as e:
        print(f"解密过程出错: {str(e)}")
    finally:
        if 'session' in locals():
            session.detach()
