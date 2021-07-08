
package Paws::Amplify::CreateDomainAssociationResult;
  use Moose;
  has DomainAssociation => (is => 'ro', isa => 'Paws::Amplify::DomainAssociation', traits => ['NameInRequest'], request_name => 'domainAssociation', required => 1);

  has _request_id => (is => 'ro', isa => 'Str');
1;

### main pod documentation begin ###

=head1 NAME

Paws::Amplify::CreateDomainAssociationResult

=head1 ATTRIBUTES


=head2 B<REQUIRED> DomainAssociation => L<Paws::Amplify::DomainAssociation>

Describes the structure of a domain association, which associates a
custom domain with an Amplify app.


=head2 _request_id => Str


=cut

