# Kiến trúc (đã thay thế)

Tài liệu "Clean Architecture & 4 microservices" trước đây không còn khớp với
code: các service `storage`/`analysis`/`collector-health` HTTP riêng, dashboard
Django và các shim `noirlycan-telemetry`/`noirlycan-console` đã bị gỡ.

Kiến trúc hiện tại là ba đơn vị triển khai (agent trên VM, backend FastAPI,
React console) với lõi phân tích thuần trong `noirlycan_core`. Xem:

- [code-map.md](code-map.md) — bố cục module, ánh xạ tới paper, luồng xử lý.
- [proposal-platform-architecture.md](proposal-platform-architecture.md) — lý do chọn modular monolith thay vì microservices.
- [../deploy/README.md](../deploy/README.md) — triển khai.
