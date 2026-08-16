# SupplyGuard 初赛 PPT

## 说明

这是一个基于 [reveal.js](https://revealjs.com/) 的单页 HTML 幻灯片，深色科技风，可直接部署到任何静态网站目录。

## 本地预览

```bash
# 进入本目录
cd ppt

# 用 Python 启动本地服务器
uv run python -m http.server 8080

# 浏览器打开
# http://localhost:8080
```

## 部署到个人网站

将整个 `ppt/` 目录上传到你网站的任意目录即可，例如：

```
https://your-site.com/supplyguard-ppt/
```

## 文件结构

```
ppt/
├── index.html    # 完整幻灯片（含 CSS、内容、SVG 图表）
└── README.md     # 本文件
```

## 操作方式

- **下一页**：方向键右 / 空格 / 点击右下角箭头
- **上一页**：方向键左
- **概览模式**：按 `Esc`
- **全屏**：按 `F`
