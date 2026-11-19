#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PyInstaller 入口：把 wafw00f 打成独立的 wafw00f.exe。

用户机器不需要安装 Python；生成物放到发布包 tools/ 或 exe 同级即可被
CyberCensus 自动发现。
"""

from wafw00f.main import main


if __name__ == "__main__":
    main()
