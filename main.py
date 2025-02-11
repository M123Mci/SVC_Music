import os
import logging
from pathlib import Path
from move_qq_files import move_music_files
from hook_qq_music import session, script  # 导入已初始化的 Frida 会话
from AssConversion import LyricsConverter
from music_video_generator import main as generate_videos

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def decrypt_qq_music():
    """解密QQ音乐文件"""
    try:
        # 获取输入目录路径
        input_dir = Path("input")
        output_dir = Path("middle/Music")
        
        if not input_dir.exists():
            logging.error("输入目录不存在")
            return False
            
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
            logging.info("没有需要解密的文件，跳过解密步骤")
            return True
            
        # 有需要解密的文件时才进行解密操作
        for file_path in input_dir.glob("*"):
            if file_path.suffix.lower() in [".mflac", ".mgg"]:
                logging.info(f"解密文件: {file_path.name}")
                
                # 修改文件扩展名
                new_ext = file_path.suffix.lower().replace("mflac", "flac").replace("mgg", "ogg")
                output_path = output_dir / f"{file_path.stem}{new_ext}"
                
                if output_path.exists():
                    logging.info(f"文件已存在，跳过: {output_path}")
                    continue
                
                try:
                    # 调用解密函数
                    script.exports_sync.decrypt(str(file_path.absolute()), str(output_path))
                    logging.info(f"解密成功: {output_path}")
                except Exception as e:
                    logging.error(f"解密失败: {file_path.name}, 错误: {str(e)}")
                    return False
        
        return True
        
    except Exception as e:
        logging.error(f"解密过程出错: {str(e)}")
        return False
    finally:
        if 'need_decrypt' in locals() and need_decrypt:
            # 只有在实际进行了解密操作时才清理会话
            session.detach()

def main():
    try:
        # 步骤1: 移动文件
        logging.info("步骤1: 移动QQ音乐文件")
        move_music_files()
        
        # 步骤2: 解密文件
        logging.info("\n步骤2: 解密加密的音乐文件")
        if not decrypt_qq_music():
            logging.error("解密过程失败，终止程序")
            return
        
        # 步骤3: 转换字幕
        logging.info("\n步骤3: 转换LRC到ASS格式")
        converter = LyricsConverter()
        converter.process_all()
        
        # 步骤4: 生成视频
        logging.info("\n步骤4: 生成KTV视频")
        generate_videos()
        
        logging.info("\n所有处理完成！")
        
    except Exception as e:
        logging.error(f"处理过程出错: {str(e)}")
        
if __name__ == "__main__":
    main() 