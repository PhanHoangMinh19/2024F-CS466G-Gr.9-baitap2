// Tạo hàm toggleTable để hiển thị/ẩn bảng
function toggleTable() {
    const tableContainer = document.getElementById('userTable');
    const isHidden = tableContainer.style.display === 'none' || tableContainer.style.display === '';

    if (isHidden) {
        tableContainer.style.display = 'block'; // Hiển thị bảng
        tableContainer.style.maxHeight = '1000px'; // Hiệu ứng trượt xuống
    } else {
        tableContainer.style.maxHeight = '0';
        setTimeout(() => {
            tableContainer.style.display = 'none'; // Ẩn bảng sau khi hiệu ứng kết thúc
        }, 500); // Đợi hiệu ứng trượt hoàn tất
    }
}


