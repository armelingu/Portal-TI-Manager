// Ativar tooltips do Bootstrap
document.addEventListener('DOMContentLoaded', function () {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Função para pesquisa dinâmica
    const searchInput = document.querySelector('.search-input');
    if (searchInput) {
        searchInput.addEventListener('input', function (e) {
            const searchTerm = e.target.value;
            const currentUrl = new URL(window.location.href);
            currentUrl.searchParams.set('search', searchTerm);
            currentUrl.searchParams.delete('page'); // Reset para primeira página
            window.location.href = currentUrl.toString();
        });
    }

    // Função para validação de formulário
    const form = document.querySelector('form');
    const btnCadastrar = document.getElementById('btnCadastrar');

    if (form) {
        form.addEventListener('submit', function (e) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;

            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    isValid = false;
                    field.classList.add('is-invalid');
                } else {
                    field.classList.remove('is-invalid');
                }
            });

            if (!isValid) {
                e.preventDefault();
                alert('Por favor, preencha todos os campos obrigatórios.');
            } else if (btnCadastrar) {
                btnCadastrar.disabled = true;
                btnCadastrar.innerHTML = `
                    <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processando...
                `;
                setTimeout(() => {
                    form.reset(); // Limpar o form logo após envio
                }, 100); // Pequeno delay só para visual não travar
            }
        });
    }

    // Formatar MAC Address
    const macInput = document.querySelector('input[name="mac_adress"]');
    if (macInput) {
        macInput.addEventListener('input', function (e) {
            let value = e.target.value.replace(/[^0-9A-Fa-f]/g, '');
            let formattedValue = '';

            for (let i = 0; i < value.length && i < 12; i++) {
                if (i > 0 && i % 2 === 0) {
                    formattedValue += ':';
                }
                formattedValue += value[i];
            }

            e.target.value = formattedValue.toUpperCase();
        });
    }

    // Formatar IP
    const ipInput = document.querySelector('input[name="endereco_ip"]');
    if (ipInput) {
        ipInput.addEventListener('input', function (e) {
            let value = e.target.value.replace(/[^0-9.]/g, '');
            let parts = value.split('.');
            let formattedValue = parts.slice(0, 4).join('.');

            e.target.value = formattedValue;
        });
    }

    // Sumir automaticamente mensagens flash
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            let fadeEffect = setInterval(function () {
                if (!alert.style.opacity) {
                    alert.style.opacity = 1;
                }
                if (alert.style.opacity > 0) {
                    alert.style.opacity -= 0.05;
                } else {
                    clearInterval(fadeEffect);
                    alert.remove();
                }
            }, 50);
        }, 2000); // Sumir depois de 2 segundos
    });
});

// Função para confirmar exclusão usando SweetAlert2
function confirmarExclusao(id) {
    Swal.fire({
        title: 'Tem certeza?',
        text: "Esta ação não poderá ser desfeita!",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#d33',
        cancelButtonColor: '#6c757d',
        confirmButtonText: 'Sim, excluir',
        cancelButtonText: 'Cancelar'
    }).then((result) => {
        if (result.isConfirmed) {
            window.location.href = '/excluir/' + id;
        }
    });
}
