// script.js - Clean e Organizado com Melhorias Profundas
// TODO: separar as funções do script em arquivos diferentes, modularizando o ambiente e melhoria para manutenção

document.addEventListener('DOMContentLoaded', function () {
    // Ativar tooltips do Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
      return new bootstrap.Tooltip(tooltipTriggerEl);
    });
  
    // Busca fluída (usuários, logs, etc.)
    const campoBusca = document.getElementById('campoBusca');
    if (campoBusca) {
      campoBusca.addEventListener('input', function (e) {
        const termo = e.target.value.toLowerCase();
        const linhasTabela = document.querySelectorAll('tbody tr');
        linhasTabela.forEach((linha) => {
          linha.style.display = linha.innerText.toLowerCase().includes(termo) ? '' : 'none';
        });
      });
    }
  
    // Validação de formulário + botão loading
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
          btnCadastrar.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span> Processando...';
          setTimeout(() => form.reset(), 100);
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
          if (i > 0 && i % 2 === 0) formattedValue += ':';
          formattedValue += value[i];
        }
        e.target.value = formattedValue.toUpperCase();
      });
    }
  
    // Formatar IP com validação
    const ipInput = document.querySelector('input[name="endereco_ip"]');
    if (ipInput) {
      ipInput.addEventListener('input', function (e) {
        let value = e.target.value.replace(/[^0-9.]/g, '');
        let parts = value.split('.');
        e.target.value = parts.slice(0, 4).join('.');
      });
    }
  
    // Sumir automaticamente mensagens flash com fade
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
      setTimeout(() => {
        let fadeEffect = setInterval(function () {
          if (!alert.style.opacity) alert.style.opacity = 1;
          if (alert.style.opacity > 0) {
            alert.style.opacity -= 0.05;
          } else {
            clearInterval(fadeEffect);
            alert.remove();
          }
        }, 50);
      }, 4000);
    });
  
    // Iniciar DataTables com botões + responsividade
    const iniciarDataTable = (idTabela) => {
      const tabela = document.getElementById(idTabela);
      if (tabela) {
        new DataTable(tabela, {
          responsive: true,
          paging: true,
          searching: true,
          ordering: true,
          language: { url: '//cdn.datatables.net/plug-ins/1.13.6/i18n/pt-BR.json' },
          dom: 'Bfrtip',
          buttons: [
            { extend: 'excelHtml5', text: 'Exportar Excel', className: 'btn btn-success' },
            { extend: 'pdfHtml5', text: 'Exportar PDF', className: 'btn btn-danger' },
            { extend: 'print', text: 'Imprimir', className: 'btn btn-primary' }
          ]
        });
      }
    }
  
    iniciarDataTable('tabelaLogs');
    iniciarDataTable('tabelaUsuarios');
  });
  
  // Confirmação SweetAlert2 - Exclusões
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
  
  function confirmarExclusaoUsuario(id) {
    Swal.fire({
      title: 'Tem certeza?',
      text: "Esta ação irá excluir o usuário do sistema!",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#d33',
      cancelButtonColor: '#6c757d',
      confirmButtonText: 'Sim, excluir',
      cancelButtonText: 'Cancelar'
    }).then((result) => {
      if (result.isConfirmed) {
        window.location.href = '/excluir_usuario/' + id;
      }
    });
  }
  