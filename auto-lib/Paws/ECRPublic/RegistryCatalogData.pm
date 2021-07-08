# Generated by default/object.tt
package Paws::ECRPublic::RegistryCatalogData;
  use Moose;
  has DisplayName => (is => 'ro', isa => 'Str', request_name => 'displayName', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::ECRPublic::RegistryCatalogData

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ECRPublic::RegistryCatalogData object:

  $service_obj->Method(Att1 => { DisplayName => $value, ..., DisplayName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ECRPublic::RegistryCatalogData object:

  $result = $service_obj->Method(...);
  $result->Att1->DisplayName

=head1 DESCRIPTION

The metadata for a public registry.

=head1 ATTRIBUTES


=head2 DisplayName => Str

The display name for a public registry. This appears on the Amazon ECR
Public Gallery.

Only accounts that have the verified account badge can have a registry
display name.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ECRPublic>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

