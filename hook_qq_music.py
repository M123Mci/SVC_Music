import frida
import os
import hashlib
from pathlib import Path
import logging

def decrypt_music_files():
    """解密QQ音乐文件"""
    try:
        print("正在连接QQ音乐进程...")
        session = frida.attach("QQMusic.exe")
        
        # 加载解密脚本
        script_path = os.path.join(os.path.dirname(__file__), "hook_qq_music.js")
        with open(script_path, 'r', encoding='utf-8') as f:
            script_code = f.read()
        script = session.create_script(script_code)
        script.load()
        
        # 获取输入目录路径
        input_dir = Path("input/music")
        output_dir = Path("middle/Music")
        
        if not input_dir.exists():
            print("! 输入目录不存在")
            return
            
        # 确保输出目录存在
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # 检查需要解密的文件
        decrypt_files = []
        for file_path in input_dir.glob("*"):
            if file_path.suffix.lower() in [".mflac", ".mgg"]:
                new_ext = file_path.suffix.lower().replace("mflac", "flac").replace("mgg", "ogg")
                output_path = output_dir / f"{file_path.stem}{new_ext}"
                if not output_path.exists():
                    decrypt_files.append((file_path, output_path))
        
        if not decrypt_files:
            print("→ 没有需要解密的文件")
            return
            
        print(f"\n开始解密，共 {len(decrypt_files)} 个文件")
        for file_path, output_path in decrypt_files:
            print(f"\n→ {file_path.name}")
            
            try:
                # 创建临时文件路径
                tmp_file_path = output_dir / hashlib.md5(file_path.name.encode()).hexdigest()
                
                # 准备文件路径
                input_file_path = str(file_path.absolute()).replace('\\', '/')
                output_file_path = str(tmp_file_path.absolute()).replace('\\', '/')
                
                # 调用解密函数
                result = script.exports_sync.decrypt(input_file_path, output_file_path)
                
                # 重命名临时文件为最终文件
                if os.path.exists(tmp_file_path):
                    os.rename(tmp_file_path, output_path)
                    print("✓ 解密成功")
                else:
                    raise Exception("临时文件未创建")
                    
            except Exception as e:
                print(f"! 解密失败: {str(e)}")
                # 清理临时文件
                if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
                    try:
                        os.remove(tmp_file_path)
                    except:
                        pass
                    
    except Exception as e:
        print(f"\n! 程序出错: {str(e)}")
    finally:
        if 'session' in locals():
            session.detach()

if __name__ == "__main__":
    decrypt_music_files()
