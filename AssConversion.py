import os
import re
import chardet
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
import logging
from datetime import datetime
from difflib import SequenceMatcher

# 修改日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # 只保留控制台输出
    ]
)

@dataclass
class LyricLine:
    """歌词行数据结构"""
    start_time: float  # 开始时间（秒）
    end_time: float   # 结束时间（秒）
    text: str         # 歌词文本
    is_current: bool = False  # 是否是当前行

class Config:
    """KTV字幕样式配置"""
    # 字体设置
    FONT_NAME = "微软雅黑"
    FONT_SIZE = 80  # 主歌词大小
    TITLE_FONT_SIZE = 60  # 标题大小
    BOLD = 1
    OUTLINE = 4  # 描边宽度
    
    # 颜色设置 (BGR格式)
    CURRENT_COLOR = "&H00D4A8AF"  # 当前行颜色（天蓝色）
    OTHER_COLOR = "&H00FFFFFF"    # 其他行颜色（白色）
    TITLE_COLOR = "&H00FFF0E0"    # 标题颜色（浅金色）
    OUTLINE_COLOR = "&H00000000"  # 描边颜色（黑色）
    
    # 位置设置 (1080p)
    TITLE_Y = 50        # 标题位置
    BOTTOM_Y1 = 900     # 上行位置
    BOTTOM_Y2 = 980     # 下行位置
    SCREEN_WIDTH = 1920
    SCREEN_MARGIN = 100  # 距离屏幕边缘的距离
    
    RESOLUTION = "1920x1080"
    FADE_DURATION = 0.1  # 渐变时间(秒)
    
    @classmethod
    def get_left_x(cls) -> int:
        """获取左侧X坐标"""
        return cls.SCREEN_MARGIN  # 从左边缘开始
        
    @classmethod
    def get_right_x(cls) -> int:
        """获取右侧X坐标"""
        return cls.SCREEN_WIDTH - cls.SCREEN_MARGIN  # 从右边缘开始

class LyricsConverter:
    """歌词转换器：将LRC/SRT转换为ASS格式"""
    
    def __init__(self):
        self.input_dir = Path("input/lyrics")  # 歌词输入目录
        self.output_dir = Path("middle/ass")   # ASS输出目录
        self.video_dir = Path("output")        # 视频输出目录
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def clean_filename(self, filename: str) -> str:
        """清理文件名，只保留ffmpeg支持的字符"""
        # 保留文件扩展名
        name, ext = os.path.splitext(filename)
        
        # 替换规则
        # 1. 移除所有撇号和引号
        name = name.replace("'", "").replace('"', "")
        # 2. 保留字母、数字、中文字符、连字符和空格
        name = re.sub(r'[^\w\u4e00-\u9fff\- ]', '', name)
        # 3. 将多个空格替换为单个空格
        name = re.sub(r'\s+', ' ', name)
        # 4. 去除首尾空格
        name = name.strip()
        
        return name + ext

    def convert_file(self, input_path: Path):
        """转换单个歌词文件"""
        try:
            self.current_file = input_path.name
            # 清理输出文件名
            clean_name = self.clean_filename(input_path.stem)
            output_path = self.output_dir / f"{clean_name}.ass"
            video_path = self.video_dir / f"{clean_name}.mp4"
            
            # 首先检查视频文件是否存在
            if video_path.exists():
                print(f"→ 视频已存在: {input_path.name}")
                return "skipped"
            
            # 检查ASS文件是否已存在
            if output_path.exists():
                print(f"→ 字幕已存在: {input_path.name}")
                return "skipped"
            
            if clean_name != input_path.stem:
                print(f"→ 清理文件名: {input_path.stem} -> {clean_name}")
            
            print(f"\n{input_path.name}")
            
            # 读取并解析歌词
            content = self.read_file(input_path)
            lyrics = (self.parse_lrc(content) if input_path.suffix.lower() == '.lrc'  
                     else self.parse_srt(content))
            
            # 生成ASS文件
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self.generate_ass_header())
                events = self.generate_events(lyrics)
                f.write('\n'.join(events))
                
            print("✓ 转换完成")
            return "converted"
            
        except Exception as e:
            print(f"! 转换失败: {str(e)}")
            raise

    def process_all(self):
        """批量处理所有歌词文件"""
        if not self.input_dir.exists():
            print(f"! 歌词目录不存在: {self.input_dir}")
            return
            
        # 统计计数
        stats = {'total': 0, 'skipped': 0, 'converted': 0, 'failed': 0}
        
        # 处理所有LRC和SRT文件
        for pattern in ['**/*.lrc', '**/*.srt']:
            for file_path in self.input_dir.glob(pattern):
                stats['total'] += 1
                try:
                    result = self.convert_file(file_path)
                    if result == "skipped":
                        stats['skipped'] += 1
                    else:
                        stats['converted'] += 1
                except Exception:
                    stats['failed'] += 1
                    continue
        
        # 输出统计结果
        if stats['total'] > 0:
            print("\n处理结果:")
            if stats['total'] == stats['skipped']:
                print("所有文件都已处理")
            else:
                print(f"总文件数: {stats['total']}")
                print(f"已转换: {stats['converted']}")
                print(f"已跳过: {stats['skipped']}")
                print(f"失败: {stats['failed']}")
        else:
            print("\n未找到歌词文件")

    def detect_encoding(self, file_path: Path) -> tuple[str, bytes]:
        """检测文件编码，返回编码和文件内容"""
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                
            # 首先尝试 chardet 检测
            result = chardet.detect(raw_data)
            detected_encoding = result.get('encoding', 'utf-8')
            confidence = result.get('confidence', 0)
            
            if confidence >= 0.8:
                return detected_encoding, raw_data
                
            # 置信度低时，尝试备选编码列表
            for encoding in ['utf-8', 'gbk', 'big5', 'shift-jis']:
                try:
                    raw_data.decode(encoding)
                    logging.info(f"使用备选编码 {encoding} 成功解码文件: {file_path}")
                    return encoding, raw_data
                except UnicodeDecodeError:
                    continue
                    
            # 如果所有备选编码都失败，返回 chardet 检测结果
            logging.warning(f"所有备选编码均解码失败，使用 chardet 检测结果: {detected_encoding}")
            return detected_encoding, raw_data
            
        except IOError as e:
            logging.error(f"读取文件失败: {file_path}, 错误: {str(e)}")
            raise
            
    def read_file(self, file_path: Path) -> str:
        """读取文件内容并转换为UTF-8"""
        try:
            encoding, raw_data = self.detect_encoding(file_path)
            try:
                return raw_data.decode(encoding)
            except UnicodeDecodeError as e:
                logging.error(f"文件解码失败: {file_path}, 编码: {encoding}, 错误: {str(e)}")
                raise
        except Exception as e:
            logging.error(f"文件处理失败: {file_path}, 错误: {str(e)}")
            raise
            
    def escape_special_chars(self, text: str) -> str:
        """处理特殊字符"""
        # 先处理 HTML 实体
        text = text.replace('&apos;', "'")
        text = text.replace('&quot;', '"')
        text = text.replace('&amp;', '&')
        text = text.replace('&lt;', '<')
        text = text.replace('&gt;', '>')
        
        # 处理其他特殊字符
        text = text.replace('\\', '\\\\')
        text = text.replace('{', '\\{')
        text = text.replace('}', '\\}')
        
        return text
        
    def parse_lrc(self, content: str) -> List[LyricLine]:
        """解析LRC格式歌词"""
        lyrics = []
        
        try:
            for line in content.splitlines():
                if not line.strip() or not line.startswith('['):
                    continue
                    
                # 提取所有时间标签
                matches = list(re.finditer(r'\[(\d{2}):(\d{2})\.(\d{2,3})\]', line))
                if not matches:
                    continue
                    
                times = []
                for match in matches:
                    try:
                        minutes = int(match.group(1))
                        seconds = int(match.group(2))
                        ms = int(match.group(3))
                        if minutes > 59 or seconds > 59 or ms > 999:
                            logging.warning(f"跳过无效时间标签: [{minutes}:{seconds}.{ms}]")
                            continue
                        total_seconds = minutes * 60 + seconds + ms / (1000 if len(match.group(3)) == 3 else 100)
                        times.append(total_seconds)
                    except ValueError as e:
                        logging.warning(f"时间标签解析失败: {match.group()}, 错误: {str(e)}")
                        continue
                        
                if not times:
                    continue
                    
                # 提取并清理歌词文本
                text = re.sub(r'\[(\d{2}):(\d{2})\.(\d{2,3})\]', '', line).strip()
                if not text:  # 跳过空歌词
                    continue
                    
                # 使用新的清理方法处理文本
                text = self.escape_special_chars(text)
                
                # 处理多时间标签
                for i, start_time in enumerate(times):
                    end_time = times[i + 1] if i + 1 < len(times) else start_time + 5
                    if end_time <= start_time:
                        end_time = start_time + 5
                    lyrics.append(LyricLine(start_time, end_time, text))
                    
            if not lyrics:
                raise ValueError("未找到有效歌词")
                
            return sorted(lyrics, key=lambda x: x.start_time)
            
        except Exception as e:
            logging.error(f"LRC解析失败: {str(e)}")
            raise

    def generate_ass_header(self) -> str:
        """生成ASS文件头部"""
        width, height = Config.RESOLUTION.split('x')
        return f"""[Script Info]
Title: KTV Style Lyrics
ScriptType: v4.00+
WrapStyle: 0
ScaledBorderAndShadow: yes
YCbCr Matrix: TV.601
PlayResX: {width}
PlayResY: {height}

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Current,{Config.FONT_NAME},{Config.FONT_SIZE},{Config.CURRENT_COLOR},&H000000FF,{Config.OUTLINE_COLOR},&H00000000,{Config.BOLD},0,1,{Config.OUTLINE},0,2,0,0,0,1
Style: Other,{Config.FONT_NAME},{Config.FONT_SIZE},{Config.OTHER_COLOR},&H000000FF,{Config.OUTLINE_COLOR},&H00000000,{Config.BOLD},0,1,{Config.OUTLINE},0,2,0,0,0,1
Style: Title,{Config.FONT_NAME},{Config.TITLE_FONT_SIZE},{Config.TITLE_COLOR},&H000000FF,{Config.OUTLINE_COLOR},&H00000000,{Config.BOLD},0,1,{Config.OUTLINE},0,8,0,0,0,1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""

    def format_time(self, seconds: float) -> str:
        """将秒转换为ASS时间格式 (H:MM:SS.cc)"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        centisecs = int((seconds * 100) % 100)
        return f"{hours}:{minutes:02d}:{secs:02d}.{centisecs:02d}"

    def parse_srt_time(self, time_str: str) -> float:
        """解析SRT时间格式 (HH:MM:SS,mmm)"""
        try:
            hours, minutes, seconds = time_str.replace(',', '.').split(':')
            hours = int(hours)
            minutes = int(minutes)
            seconds = float(seconds)
            
            # 验证时间值的合法性
            if hours > 23 or minutes > 59 or seconds >= 60:
                raise ValueError(f"无效的时间值: {time_str}")
                
            return float(hours) * 3600 + float(minutes) * 60 + seconds
        except Exception as e:
            raise ValueError(f"时间格式解析失败: {time_str}, 错误: {str(e)}")

    def parse_srt(self, content: str) -> List[LyricLine]:
        """解析SRT格式字幕"""
        lyrics = []
        
        matches = re.finditer(r'(\d+)\n(\d{2}:\d{2}:\d{2},\d{3}) --> (\d{2}:\d{2}:\d{2},\d{3})\n((?:.*\n)*?)\n', content)
        for match in matches:
            try:
                start_time = self.parse_srt_time(match.group(2))
                end_time = self.parse_srt_time(match.group(3))
                text = match.group(4).strip().replace('\n', ' ')
                text = self.escape_special_chars(text)
                lyrics.append(LyricLine(start_time, end_time, text))
            except ValueError as e:
                logging.warning(f"跳过无效字幕行: {match.group()}, 错误: {str(e)}")
                continue
        
        return sorted(lyrics, key=lambda x: x.start_time)

    def generate_ktv_effects(self, text: str, is_current: bool = True, offset: int = 0) -> str:
        """生成KTV特效文本"""
        if not text.strip():
            return text
        
        # 根据偏移量计算动画效果
        if offset == -2:  # 最上面一行
            return f"{{\\fad(0,{int(Config.FADE_DURATION*1000)})}}{text}"
        elif offset == 2:  # 最下面一行
            return f"{{\\fad({int(Config.FADE_DURATION*1000)},0)}}{text}"
        else:
            return text

    def parse_title_from_filename(self, filename: str) -> tuple[str, str]:
        """从文件名解析歌曲名和作者"""
        # 移除扩展名
        name = os.path.splitext(filename)[0]
        # 尝试分割作者和歌名
        parts = name.split(' - ', 1)
        if len(parts) == 2:
            artist, title = parts
        else:
            artist = "未知歌手"
            title = name
        return artist, title

    def generate_events(self, lyrics: List[LyricLine]) -> List[str]:
        """生成ASS Events部分"""
        events = []
        
        # 添加标题显示
        artist, title = self.parse_title_from_filename(Path(self.current_file).name)
        title_text = f"{artist} - {title}"
        events.append(
            f"Dialogue: 0,0:00:00.00,99:00:00.00,Title,,0,0,0,,"
            f"{{\\pos({Config.SCREEN_WIDTH // 2},{Config.TITLE_Y})\\an8}}{title_text}"
        )
        
        # 生成歌词事件
        for i in range(len(lyrics)):
            current_line = lyrics[i]
            current_start = self.format_time(current_line.start_time)
            
            if i < len(lyrics) - 1:
                next_line = lyrics[i + 1]
                time_gap = next_line.start_time - current_line.start_time
                
                if time_gap > 15:  # 如果间隔超过15秒
                    current_end = self.format_time(current_line.end_time + 6)
                    next_preview_start = self.format_time(next_line.start_time - 3)
                    next_actual_start = self.format_time(next_line.start_time)
                    
                    if i % 2 == 0:  # 偶数行
                        # 当前行（有颜色）在左上
                        events.append(
                            f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                            f"{{\\pos({Config.get_left_x()},{Config.BOTTOM_Y1})\\an1}}{current_line.text}"
                        )
                        # 下一行（白色）在右下
                        events.append(
                            f"Dialogue: 0,{next_preview_start},{next_actual_start},Other,,0,0,0,,"
                            f"{{\\pos({Config.get_right_x()},{Config.BOTTOM_Y2})\\an3}}{next_line.text}"
                        )
                    else:  # 奇数行
                        # 当前行（有颜色）在右下
                        events.append(
                            f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                            f"{{\\pos({Config.get_right_x()},{Config.BOTTOM_Y2})\\an3}}{current_line.text}"
                        )
                        # 下一行（白色）在左上
                        events.append(
                            f"Dialogue: 0,{next_preview_start},{next_actual_start},Other,,0,0,0,,"
                            f"{{\\pos({Config.get_left_x()},{Config.BOTTOM_Y1})\\an1}}{next_line.text}"
                        )
                else:
                    current_end = self.format_time(next_line.start_time)
                    
                    if i % 2 == 0:  # 偶数行
                        # 当前行（有颜色）在左上
                        events.append(
                            f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                            f"{{\\pos({Config.get_left_x()},{Config.BOTTOM_Y1})\\an1}}{current_line.text}"
                        )
                        # 下一行（白色）在右下
                        events.append(
                            f"Dialogue: 0,{current_start},{current_end},Other,,0,0,0,,"
                            f"{{\\pos({Config.get_right_x()},{Config.BOTTOM_Y2})\\an3}}{next_line.text}"
                        )
                    else:  # 奇数行
                        # 当前行（有颜色）在右下
                        events.append(
                            f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                            f"{{\\pos({Config.get_right_x()},{Config.BOTTOM_Y2})\\an3}}{current_line.text}"
                        )
                        # 下一行（白色）在左上
                        events.append(
                            f"Dialogue: 0,{current_start},{current_end},Other,,0,0,0,,"
                            f"{{\\pos({Config.get_left_x()},{Config.BOTTOM_Y1})\\an1}}{next_line.text}"
                        )
            else:
                # 最后一行
                current_end = self.format_time(current_line.end_time)
                if i % 2 == 0:  # 偶数行，在左上
                    events.append(
                        f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                        f"{{\\pos({Config.get_left_x()},{Config.BOTTOM_Y1})\\an1}}{current_line.text}"
                    )
                else:  # 奇数行，在右下
                    events.append(
                        f"Dialogue: 0,{current_start},{current_end},Current,,0,0,0,,"
                        f"{{\\pos({Config.get_right_x()},{Config.BOTTOM_Y2})\\an3}}{current_line.text}"
                    )
        
        return events

    def get_text_width(self, text: str) -> int:
        """估算文本宽度（简化版）"""
        # 假设每个字符宽度为FONT_SIZE/2
        return int(len(text) * Config.FONT_SIZE / 2)

def clean_text(text: str) -> str:
    """清理文本中的特殊字符"""
    # 替换 HTML 实体
    text = text.replace('&apos;', "'")
    text = text.replace('&quot;', '"')
    text = text.replace('&amp;', '&')
    text = text.replace('&lt;', '<')
    text = text.replace('&gt;', '>')
    
    # 移除 ASS 标签
    text = re.sub(r'{\\[^}]*}', '', text)
    
    # 标准化标点符号
    text = text.replace('，', ',')
    text = text.replace('。', '.')
    text = text.replace('：', ':')
    text = text.replace('；', ';')
    text = text.replace('"', '"')
    text = text.replace('"', '"')
    text = text.replace(''', "'")
    text = text.replace(''', "'")
    
    # 移除多余的空格和标点
    text = re.sub(r'\s+', ' ', text)  # 多个空格替换为单个
    text = re.sub(r'[,\s]*,[,\s]*', ', ', text)  # 规范化逗号
    text = re.sub(r'[.\s]*\.[.\s]*', '. ', text)  # 规范化句点
    text = text.strip()
    
    return text

def convert_lrc_to_ass(lrc_path: str, output_dir: str = None) -> str:
    """将LRC文件转换为ASS格式"""
    if output_dir is None:
        output_dir = 'middle/ass'
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    
    # 读取LRC文件
    with open(lrc_path, 'r', encoding='utf-8') as f:
        lrc_content = f.readlines()
    
    # 提取歌曲信息
    title = Path(lrc_path).stem
    title = clean_text(title)  # 清理标题中的特殊字符
    
    # 创建ASS文件内容
    ass_content = [
        '[Script Info]',
        'Title: KTV Style Lyrics',
        'ScriptType: v4.00+',
        'WrapStyle: 0',
        'ScaledBorderAndShadow: yes',
        'YCbCr Matrix: TV.601',
        'PlayResX: 1920',
        'PlayResY: 1080',
        '',
        '[V4+ Styles]',
        'Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding',
        'Style: Current,微软雅黑,80,&H00D4A8AF,&H000000FF,&H00000000,&H00000000,1,0,1,4,0,2,0,0,0,1',
        'Style: Other,微软雅黑,80,&H00FFFFFF,&H000000FF,&H00000000,&H00000000,1,0,1,4,0,2,0,0,0,1',
        'Style: Title,微软雅黑,60,&H00FFF0E0,&H000000FF,&H00000000,&H00000000,1,0,1,4,0,8,0,0,0,1',
        '',
        '[Events]',
        'Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text'
    ]
    
    # 添加标题
    ass_content.append(f'Dialogue: 0,0:00:00.00,99:00:00.00,Title,,0,0,0,,{{\\pos(960,50)\\an8}}{title}')
    
    # 解析LRC时间标记和歌词
    lyrics = []
    for line in lrc_content:
        line = line.strip()
        if not line or line.startswith('[ti:') or line.startswith('[ar:'):
            continue
            
        match = re.match(r'\[(\d+):(\d+)\.(\d+)\](.*)', line)
        if match:
            minutes, seconds, centiseconds, text = match.groups()
            start_time = int(minutes) * 60 + int(seconds) + int(centiseconds) / 100
            text = clean_text(text)  # 清理歌词中的特殊字符
            if text:  # 只添加非空歌词
                lyrics.append((start_time, text))
    
    # 生成ASS对话行
    for i in range(len(lyrics)):
        start_time = lyrics[i][0]
        text = lyrics[i][1]
        
        # 计算结束时间
        if i < len(lyrics) - 1:
            end_time = lyrics[i + 1][0]
        else:
            end_time = start_time + 5  # 最后一行默认显示5秒
        
        # 转换时间格式
        start = f'{int(start_time/3600):01d}:{int(start_time/60%60):02d}:{start_time%60:05.2f}'
        end = f'{int(end_time/3600):01d}:{int(end_time/60%60):02d}:{end_time%60:05.2f}'
        
        # 添加当前行和下一行
        ass_content.append(f'Dialogue: 0,{start},{end},Current,,0,0,0,,{{\\pos(985,980)\\an4}}{text}')
        if i < len(lyrics) - 1:
            ass_content.append(f'Dialogue: 0,{start},{end},Other,,0,0,0,,{{\\pos(935,900)\\an6}}{lyrics[i+1][1]}')
    
    # 写入ASS文件
    output_path = os.path.join(output_dir, f'{title}.ass')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(ass_content))
    
    return output_path

if __name__ == "__main__":
    converter = LyricsConverter()
    converter.process_all() 