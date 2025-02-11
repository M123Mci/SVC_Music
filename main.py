import os
from move_qq_files import move_music_files
from hook_qq_music import decrypt_music_files
from AssConversion import LyricsConverter
from music_video_generator import main as generate_videos

def main():
    print("\n=== 1. 移动QQ音乐文件 ===")
    move_music_files()
    
    print("\n=== 2. 解密加密的音乐文件 ===")
    decrypt_music_files()
    
    print("\n=== 3. 转换歌词为ASS格式 ===")
    converter = LyricsConverter()
    converter.process_all()
    
    print("\n=== 4. 生成音乐视频 ===")
    generate_videos()

if __name__ == "__main__":
    main()