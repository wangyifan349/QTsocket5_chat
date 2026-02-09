from flask import Flask, render_template_string, request, send_from_directory, redirect, url_for, jsonify
from flask_httpauth import HTTPBasicAuth
import os

app = Flask(__name__)
auth = HTTPBasicAuth()

# 配置上传文件夹
UPLOAD_FOLDER = './static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 创建上传文件夹（如果不存在）
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 定义用户名和密码，实际应用中应该从数据库获取
users = {
    "admin": "password123",  # 用户名: 密码
}

# 基本认证验证函数
@auth.verify_password
def verify_password(username, password):
    if users.get(username) == password:
        return username

# 上传的文件不做任何限制
# 判断文件是否存在（不再限制文件类型）
def allowed_file(filename):
    return '.' in filename

# 首页，列出文件列表
@app.route('/')
@auth.login_required  # 需要认证才能访问
def index():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template_string(TEMPLATE, files=files)

# 上传文件
@app.route('/upload', methods=['POST'])
@auth.login_required  # 需要认证才能上传
def upload_file():
    if 'files[]' not in request.files:
        return redirect(request.url)
    
    files = request.files.getlist('files[]')
    for file in files:
        if file:
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filename)
    return redirect(url_for('index'))

# 下载文件
@app.route('/download/<filename>')
@auth.login_required  # 需要认证才能下载
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# 删除文件
@app.route('/delete/<filename>', methods=['POST'])
@auth.login_required  # 需要认证才能删除
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return jsonify({'status': 'success', 'message': 'File deleted successfully'})

# 前端模板，使用Bootstrap美化页面
TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>简单云盘</title>
    <!-- 引入Bootstrap样式 -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .container { max-width: 900px; }
        .file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 300px; }
        .context-menu { 
            display: none; 
            position: absolute; 
            background-color: white; 
            box-shadow: 0px 4px 6px rgba(0,0,0,0.1); 
            border-radius: 4px;
            z-index: 1000;
        }
        .context-menu a { 
            display: block; 
            padding: 8px 12px; 
            text-decoration: none; 
            color: #333; 
        }
        .context-menu a:hover { background-color: #f0f0f0; }
    </style>
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">简单云盘</h1>
        
        <!-- 上传文件部分 -->
        <h3 class="mt-4">上传文件</h3>
        <form action="/upload" method="POST" enctype="multipart/form-data">
            <div class="mb-3">
                <input type="file" class="form-control" name="files[]" multiple required>
            </div>
            <button type="submit" class="btn btn-primary">上传</button>
        </form>

        <!-- 文件列表部分 -->
        <h3 class="mt-5">文件列表</h3>
        <table class="table table-bordered table-striped">
            <thead>
                <tr>
                    <th>文件名</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody id="file-list">
                {% for file in files %}
                    <tr class="file-item" data-filename="{{ file }}">
                        <td class="file-name">{{ file }}</td>
                        <td>
                            <a href="{{ url_for('download_file', filename=file) }}" class="btn btn-success btn-sm" target="_blank">
                                下载
                            </a>
                        </td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <!-- 右键菜单 -->
    <div id="context-menu" class="context-menu">
        <a href="#" id="download-option">下载</a>
        <a href="#" id="delete-option">删除</a>
    </div>

    <!-- 引入Bootstrap和AJAX -->
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>

    <script>
        // 显示右键菜单
        var currentFile = '';
        $(document).on('contextmenu', '.file-item', function(e) {
            e.preventDefault();
            currentFile = $(this).data('filename');
            $('#context-menu').css({
                top: e.pageY + 'px',
                left: e.pageX + 'px'
            }).show();
        });

        // 隐藏右键菜单
        $(document).click(function() {
            $('#context-menu').hide();
        });

        // 下载文件
        $('#download-option').click(function() {
            window.location.href = '/download/' + currentFile;
            $('#context-menu').hide();
        });

        // 删除文件
        $('#delete-option').click(function() {
            if (confirm('确定要删除该文件吗?')) {
                $.ajax({
                    url: '/delete/' + currentFile,
                    method: 'POST',
                    success: function(response) {
                        if (response.status === 'success') {
                            alert(response.message);
                            location.reload();  // 刷新页面
                        } else {
                            alert('删除失败');
                        }
                    }
                });
            }
            $('#context-menu').hide();
        });
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)
