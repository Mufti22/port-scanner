import nmap

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-p 1-65535 -T4')  # Увеличим уровень агрессивности до -T4

    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                state = nm[host][proto][port]['state']
                if state == 'open':
                    open_ports.append(port)
    return open_ports

def main():
    try:
        num_ips = int(input("Введите количество IP адресов для сканирования: "))
        if num_ips <= 0:
            print("Некорректное количество IP адресов.")
            return

        ip_addresses = []
        for i in range(num_ips):
            ip = input(f"Введите IP адрес {i+1}: ")
            ip_addresses.append(ip)

        print("\nСканирование портов...")

        print("\nРезультаты сканирования:")
        print("{:<15} {:<10}".format("IP адрес", "Открытые порты"))

        for ip in ip_addresses:
            open_ports = scan_ports(ip)
            if open_ports:
                print("{:<15} {:<10}".format(ip, ", ".join(map(str, open_ports))))
            else:
                print("{:<15} {:<10}".format(ip, "Нет открытых портов"))

    except ValueError:
        print("Ошибка: Введите корректное число IP адресов.")
    except KeyboardInterrupt:
        print("Сканирование остановлено пользователем.")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    main()